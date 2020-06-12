/*!
 * Copyright 2017-2018 by Contributors
 * \file updater_quantile_hist.cc
 * \brief use quantized feature values to construct a tree
 * \author Philip Cho, Tianqi Checn
 */
#include <dmlc/timer.h>
#include <rabit/rabit.h>
#include <xgboost/logging.h>
#include <xgboost/tree_updater.h>

#include <cmath>
#include <memory>
#include <vector>
#include <algorithm>
#include <queue>
#include <iomanip>
#include <numeric>
#include <string>
#include <utility>

#include <xgboost/tree/param.h>
#include <xgboost/tree/updater_quantile_hist.h>
#include <xgboost/tree/split_evaluator.h>
#include <xgboost/common/random.h>
#include <xgboost/common/hist_util.h>
#include <xgboost/common/row_set.h>
#include <xgboost/common/column_matrix.h>

namespace xgboost {
namespace tree {
namespace {

// NOTE: works due to we are expanding a binary complete tree.
std::pair<size_t, size_t> GetLevelNodeRange(size_t nid) {
  size_t level = 0;
  size_t level_width = 1 << level;
  size_t level_begin_nid = 0;
  size_t level_end_nid = level_begin_nid + level_width;
  while (!(nid >= level_begin_nid && nid < level_end_nid)) {
    level++;
    level_width = 1 << level;
    level_begin_nid = level_end_nid;
    level_end_nid = level_begin_nid + level_width;
  }
  return std::make_pair(level_begin_nid, level_end_nid);
}

}  // namespace

DMLC_REGISTRY_FILE_TAG(updater_quantile_hist);

void QuantileHistMaker::Init(const std::vector<std::pair<std::string, std::string> >& args) {
  // initialize pruner
  if (!pruner_) {
    pruner_.reset(TreeUpdater::Create("prune"));
  }
  pruner_->Init(args);
  param_.InitAllowUnknown(args);
  is_gmat_initialized_ = false;

  // initialise the split evaluator
  if (!spliteval_) {
    spliteval_.reset(SplitEvaluator::Create(param_.split_evaluator));
  }

  spliteval_->Init(args);
}

void QuantileHistMaker::Update(HostDeviceVector<GradientPair> *gpair,
                               DMatrix *dmat,
                               const std::vector<RegTree *> &trees) {
  if (is_gmat_initialized_ == false) {
    double tstart = dmlc::GetTime();
    gmat_.Init(dmat, static_cast<uint32_t>(param_.max_bin));
    column_matrix_.Init(gmat_, param_.sparse_threshold);
    if (param_.enable_feature_grouping > 0) {
      gmatb_.Init(gmat_, column_matrix_, param_);
    }
    is_gmat_initialized_ = true;
    LOG(INFO) << "Generating gmat: " << dmlc::GetTime() - tstart << " sec";
  }
  // rescale learning rate according to size of trees
  float lr = param_.learning_rate;
  param_.learning_rate = lr / trees.size();
  // build tree
  if (!builder_) {
    builder_.reset(new Builder(
        param_,
        std::move(pruner_),
        std::unique_ptr<SplitEvaluator>(spliteval_->GetHostClone())));
  }
  for (auto tree : trees) {
    builder_->Update(gmat_, gmatb_, column_matrix_, gpair, dmat, tree);
  }
  param_.learning_rate = lr;
}

bool QuantileHistMaker::UpdatePredictionCache(
    const DMatrix* data,
    HostDeviceVector<bst_float>* out_preds) {
  if (!builder_ || param_.subsample < 1.0f) {
    return false;
  } else {
    return builder_->UpdatePredictionCache(data, out_preds);
  }
}

void QuantileHistMaker::Builder::SyncHistograms(
    int starting_index,
    int sync_count,
    RegTree *p_tree) {
  builder_monitor_.Start("SyncHistograms");
  this->histred_.Allreduce(hist_[starting_index].data(), hist_builder_.GetNumBins() * sync_count);
  // use Subtraction Trick
  for (auto const& node_pair : nodes_for_subtraction_trick_) {
    hist_.AddHistRow(node_pair.first);
    SubtractionTrick(hist_[node_pair.first], hist_[node_pair.second],
                     hist_[(*p_tree)[node_pair.first].Parent()]);
  }
  builder_monitor_.Stop("SyncHistograms");
}

void QuantileHistMaker::Builder::BuildLocalHistograms(
    int *starting_index,
    int *sync_count,
    const GHistIndexMatrix &gmat,
    const GHistIndexBlockMatrix &gmatb,
    RegTree *p_tree,
    const std::vector<GradientPair> &gpair_h) {
  builder_monitor_.Start("BuildLocalHistograms");
  for (auto const& entry : qexpand_depth_wise_) {
    int nid = entry.nid;
    RegTree::Node &node = (*p_tree)[nid];
    if (rabit::IsDistributed()) {
      if (node.IsRoot() || node.IsLeftChild()) {
        hist_.AddHistRow(nid);
        // in distributed setting, we always calculate from left child or root node
        BuildHist(gpair_h, row_set_collection_[nid], gmat, gmatb, hist_[nid], false);
        if (!node.IsRoot()) {
          nodes_for_subtraction_trick_[(*p_tree)[node.Parent()].RightChild()] = nid;
        }
        (*sync_count)++;
        (*starting_index) = std::min((*starting_index), nid);
      }
    } else {
      if (!node.IsRoot() && node.IsLeftChild() &&
          (row_set_collection_[nid].Size() <
           row_set_collection_[(*p_tree)[node.Parent()].RightChild()].Size())) {
        hist_.AddHistRow(nid);
        BuildHist(gpair_h, row_set_collection_[nid], gmat, gmatb, hist_[nid], false);
        nodes_for_subtraction_trick_[(*p_tree)[node.Parent()].RightChild()] = nid;
        (*sync_count)++;
        (*starting_index) = std::min((*starting_index), nid);
      } else if (!node.IsRoot() && !node.IsLeftChild() &&
                 (row_set_collection_[nid].Size() <=
                  row_set_collection_[(*p_tree)[node.Parent()].LeftChild()].Size())) {
        hist_.AddHistRow(nid);
        BuildHist(gpair_h, row_set_collection_[nid], gmat, gmatb, hist_[nid], false);
        nodes_for_subtraction_trick_[(*p_tree)[node.Parent()].LeftChild()] = nid;
        (*sync_count)++;
        (*starting_index) = std::min((*starting_index), nid);
      } else if (node.IsRoot()) {
        hist_.AddHistRow(nid);
        BuildHist(gpair_h, row_set_collection_[nid], gmat, gmatb, hist_[nid], false);
        (*sync_count)++;
        (*starting_index) = std::min((*starting_index), nid);
      }
    }
  }
  builder_monitor_.Stop("BuildLocalHistograms");
}

void QuantileHistMaker::Builder::BuildNodeStats(
    const GHistIndexMatrix &gmat,
    DMatrix *p_fmat,
    RegTree *p_tree,
    const std::vector<GradientPair> &gpair_h) {
  builder_monitor_.Start("BuildNodeStats");
  for (auto const& entry : qexpand_depth_wise_) {
    int nid = entry.nid;
    this->InitNewNode(nid, gmat, gpair_h, *p_fmat, *p_tree);
    // add constraints
    if (!(*p_tree)[nid].IsLeftChild() && !(*p_tree)[nid].IsRoot()) {
      // it's a right child
      auto parent_id = (*p_tree)[nid].Parent();
      auto left_sibling_id = (*p_tree)[parent_id].LeftChild();
      auto parent_split_feature_id = snode_[parent_id].best.SplitIndex();
      spliteval_->AddSplit(parent_id, left_sibling_id, nid, parent_split_feature_id,
                           snode_[left_sibling_id].weight, snode_[nid].weight);
    }
  }
  builder_monitor_.Stop("BuildNodeStats");
}

void QuantileHistMaker::Builder::EvaluateSplits(
    const GHistIndexMatrix &gmat,
    const ColumnMatrix &column_matrix,
    DMatrix *p_fmat,
    RegTree *p_tree,
    int *num_leaves,
    int depth,
    unsigned *timestamp,
    std::vector<ExpandEntry> *temp_qexpand_depth) {
  for (auto const& entry : qexpand_depth_wise_) {
    int nid = entry.nid;
    this->EvaluateSplit(nid, gmat, hist_, *p_fmat, *p_tree);
    // For oblivious: we keep expanding nodes since we wanna protect tree
    // structures.
    const bool kMaxDepthReached =
        (param_.max_depth > 0 && depth == param_.max_depth);
    const bool kEnforceMaxDepth = true;
    if (kMaxDepthReached ||
        (!common::ObliviousEnabled() && !kEnforceMaxDepth &&
         (snode_[nid].best.loss_chg < kRtEps ||
          (param_.max_leaves > 0 && (*num_leaves) == param_.max_leaves)))) {
      (*p_tree)[nid].SetLeaf(snode_[nid].weight * param_.learning_rate);
    } else {
      this->ApplySplit(nid, gmat, column_matrix, hist_, *p_fmat, p_tree);
      int left_id = (*p_tree)[nid].LeftChild();
      int right_id = (*p_tree)[nid].RightChild();
      temp_qexpand_depth->push_back(
          ExpandEntry(left_id, p_tree->GetDepth(left_id), 0.0, (*timestamp)++));
      temp_qexpand_depth->push_back(ExpandEntry(
          right_id, p_tree->GetDepth(right_id), 0.0, (*timestamp)++));
      // - 1 parent + 2 new children
      (*num_leaves)++;
    }
  }

  // Oblivious split.
  ApplySplitLevelWise(gmat, column_matrix, p_tree, depth);
  // For debug.
  const bool kDebugHistogram = false;
  if (kDebugHistogram) {
    for (auto& entry : qexpand_depth_wise_) {
      std::stringstream ss;
      for (size_t fid = 0; fid < column_matrix.GetNumFeature(); ++fid) {
        ss << hist_[entry.nid][fid].sum_grad << ", ";
        ss << hist_[entry.nid][fid].sum_hess << ", ";
      }
      LOG(INFO) << "nid=" << entry.nid << ", hist=" << ss.str();
    }
  }

  LOG(DEBUG) << "DEBUG: finished at depth=" << depth;
}

void QuantileHistMaker::Builder::ApplySplitLevelWise(
    const GHistIndexMatrix& gmat, const ColumnMatrix& column_matrix,
    const RegTree* p_tree, int depth) {
  if (depth < this->param_.max_depth && !qexpand_depth_wise_.empty() &&
      xgboost::common::ObliviousEnabled()) {
    // For debug.
    std::vector<size_t> node_samples_count;
    std::vector<int> next_level_ids;

    // Pre-compute level containers for later `oaccess`.
    std::vector<int> vec_split_cond;
    std::vector<int> vec_split_fid;
    std::vector<uint8_t> vec_default_left;
    std::vector<int> left_childs;
    std::vector<int> right_childs;
    size_t base_nid = this->qexpand_depth_wise_.front().nid;
    for (auto const& entry : this->qexpand_depth_wise_) {
      int nid = entry.nid;
      const bst_uint fid = (*p_tree)[nid].SplitIndex();
      const bst_float split_pt = (*p_tree)[nid].SplitCond();
      const uint32_t lower_bound = gmat.cut.row_ptr[fid];
      const uint32_t upper_bound = gmat.cut.row_ptr[fid + 1];
      int32_t split_cond = -1;
      // convert floating-point split_pt into corresponding bin_id
      // split_cond = -1 indicates that split_pt is less than all known cut
      // points
      CHECK_LT(upper_bound,
               static_cast<uint32_t>(std::numeric_limits<int32_t>::max()));
      for (uint32_t i = lower_bound; i < upper_bound; ++i) {
        ObliviousAssign(split_pt == gmat.cut.cut[i], static_cast<int>(i),
                        split_cond, &split_cond);
      }
      LOG(DEBUG) << "DEBUG_OBL: split_cond[" << nid << "] = " << split_cond;

      vec_split_cond.push_back(split_cond);
      vec_split_fid.push_back(fid);
      left_childs.push_back((*p_tree)[nid].LeftChild());
      right_childs.push_back((*p_tree)[nid].RightChild());
      vec_default_left.push_back((*p_tree)[nid].DefaultLeft() ? 1 : 0);
    }

    // Efficient level-wise method. O(n_rows * O(`oaccess`)).
    const size_t nrows = gmat.row_ptr.size() - 1;
    for (size_t row_idx = 0; row_idx < nrows; ++row_idx) {
      const size_t level_index =
          this->row_node_map_.GetRowTarget(row_idx, depth) - base_nid;
      CHECK(level_index < vec_split_fid.size());
      // const xgboost::bst_uint fid = vec_split_fid[level_index];
      // const int split_cond = vec_split_cond[level_index];
      // const bool default_left = vec_default_left[level_index] == 1;
      // const int left_id = left_childs[level_index];
      // const int right_id = right_childs[level_index];
      const xgboost::bst_uint fid = ObliviousArrayAccess(
          vec_split_fid.data(), level_index, vec_split_fid.size());
      const int split_cond = ObliviousArrayAccess(
          vec_split_cond.data(), level_index, vec_split_cond.size());
      const bool default_left = ObliviousEqual(
          ObliviousArrayAccess(vec_default_left.data(), level_index,
                               vec_default_left.size()),
          static_cast<uint8_t>(1));
      const int left_id = ObliviousArrayAccess(left_childs.data(), level_index,
                                               left_childs.size());
      const int right_id = ObliviousArrayAccess(
          right_childs.data(), level_index, right_childs.size());

      // NOTE: oaccess
      const uint32_t fbin_idx =
          column_matrix.OGetRowFeatureBinIndex(row_idx, fid);

      // Normal value case.
      int target_id = ObliviousChoose(
          ObliviousLessOrEqual(static_cast<int64_t>(fbin_idx),
                               static_cast<int64_t>(split_cond)),
          left_id, right_id);
      // Missing value case.
      const int missing_value_target_id = ObliviousChoose(default_left, left_id, right_id);
      ObliviousAssign(
          // fbin_idx == std::numeric_limits<uint32_t>::max(),
          ObliviousEqual(fbin_idx, std::numeric_limits<uint32_t>::max()),
          missing_value_target_id, target_id, &target_id);
      CHECK(depth + 1 <= this->param_.max_depth);
      this->row_node_map_.SetRowTarget(row_idx, depth + 1, target_id);

      if (xgboost::common::ObliviousDebugCheckEnabled()) {
        if (target_id >= node_samples_count.size()) {
          node_samples_count.resize(target_id + 1, 0);
        }
        node_samples_count[target_id]++;
      }
    }

    if (xgboost::common::ObliviousDebugCheckEnabled()) {
      std::copy(left_childs.begin(), left_childs.end(),
                std::back_inserter(next_level_ids));
      std::copy(right_childs.begin(), right_childs.end(),
                std::back_inserter(next_level_ids));
      for (auto nid : next_level_ids) {
        const auto& row_set = this->row_set_collection_[nid];
        CHECK_EQ(row_set.Size(), node_samples_count[nid]);
      }
    }
  }
}

void QuantileHistMaker::Builder::ExpandWithDepthWidth(
  const GHistIndexMatrix &gmat,
  const GHistIndexBlockMatrix &gmatb,
  const ColumnMatrix &column_matrix,
  DMatrix *p_fmat,
  RegTree *p_tree,
  const std::vector<GradientPair> &gpair_h) {
  unsigned timestamp = 0;
  int num_leaves = 0;

  // in depth_wise growing, we feed loss_chg with 0.0 since it is not used anyway
  qexpand_depth_wise_.emplace_back(ExpandEntry(0, p_tree->GetDepth(0), 0.0, timestamp++));
  ++num_leaves;
  for (int depth = 0; depth < param_.max_depth + 1; depth++) {
    int starting_index = std::numeric_limits<int>::max();
    int sync_count = 0;
    std::vector<ExpandEntry> temp_qexpand_depth;
    if (common::ObliviousEnabled()) {
      BuildLocalHistogramsLevelWise(&starting_index, &sync_count, gmat, gmatb,
                                    p_tree, gpair_h);
    } else {
      BuildLocalHistograms(&starting_index, &sync_count, gmat, gmatb, p_tree,
                           gpair_h);
    }
    SyncHistograms(starting_index, sync_count, p_tree);
    BuildNodeStats(gmat, p_fmat, p_tree, gpair_h);
    EvaluateSplits(gmat, column_matrix, p_fmat, p_tree, &num_leaves, depth, &timestamp,
                   &temp_qexpand_depth);
    // clean up
    qexpand_depth_wise_.clear();
    nodes_for_subtraction_trick_.clear();
    if (temp_qexpand_depth.empty()) {
      break;
    } else {
      qexpand_depth_wise_ = temp_qexpand_depth;
      temp_qexpand_depth.clear();
    }
  }
}

void QuantileHistMaker::Builder::ExpandWithLossGuide(
    const GHistIndexMatrix& gmat,
    const GHistIndexBlockMatrix& gmatb,
    const ColumnMatrix& column_matrix,
    DMatrix* p_fmat,
    RegTree* p_tree,
    const std::vector<GradientPair>& gpair_h) {

  unsigned timestamp = 0;
  int num_leaves = 0;

  for (int nid = 0; nid < p_tree->param.num_roots; ++nid) {
    hist_.AddHistRow(nid);
    BuildHist(gpair_h, row_set_collection_[nid], gmat, gmatb, hist_[nid], true);

    this->InitNewNode(nid, gmat, gpair_h, *p_fmat, *p_tree);

    this->EvaluateSplit(nid, gmat, hist_, *p_fmat, *p_tree);
    qexpand_loss_guided_->push(ExpandEntry(nid, p_tree->GetDepth(nid),
                               snode_[nid].best.loss_chg,
                               timestamp++));
    ++num_leaves;
  }

  while (!qexpand_loss_guided_->empty()) {
    const ExpandEntry candidate = qexpand_loss_guided_->top();
    const int nid = candidate.nid;
    qexpand_loss_guided_->pop();
    if (candidate.loss_chg <= kRtEps
        || (param_.max_depth > 0 && candidate.depth == param_.max_depth)
        || (param_.max_leaves > 0 && num_leaves == param_.max_leaves) ) {
      (*p_tree)[nid].SetLeaf(snode_[nid].weight * param_.learning_rate);
    } else {
      this->ApplySplit(nid, gmat, column_matrix, hist_, *p_fmat, p_tree);

      const int cleft = (*p_tree)[nid].LeftChild();
      const int cright = (*p_tree)[nid].RightChild();
      hist_.AddHistRow(cleft);
      hist_.AddHistRow(cright);

      if (rabit::IsDistributed()) {
        // in distributed mode, we need to keep consistent across workers
        BuildHist(gpair_h, row_set_collection_[cleft], gmat, gmatb, hist_[cleft], true);
        SubtractionTrick(hist_[cright], hist_[cleft], hist_[nid]);
      } else {
        if (row_set_collection_[cleft].Size() < row_set_collection_[cright].Size()) {
          BuildHist(gpair_h, row_set_collection_[cleft], gmat, gmatb, hist_[cleft], true);
          SubtractionTrick(hist_[cright], hist_[cleft], hist_[nid]);
        } else {
          BuildHist(gpair_h, row_set_collection_[cright], gmat, gmatb, hist_[cright], true);
          SubtractionTrick(hist_[cleft], hist_[cright], hist_[nid]);
        }
      }

      this->InitNewNode(cleft, gmat, gpair_h, *p_fmat, *p_tree);
      this->InitNewNode(cright, gmat, gpair_h, *p_fmat, *p_tree);
      bst_uint featureid = snode_[nid].best.SplitIndex();
      spliteval_->AddSplit(nid, cleft, cright, featureid,
                           snode_[cleft].weight, snode_[cright].weight);

      this->EvaluateSplit(cleft, gmat, hist_, *p_fmat, *p_tree);
      this->EvaluateSplit(cright, gmat, hist_, *p_fmat, *p_tree);

      qexpand_loss_guided_->push(ExpandEntry(cleft, p_tree->GetDepth(cleft),
                                 snode_[cleft].best.loss_chg,
                                 timestamp++));
      qexpand_loss_guided_->push(ExpandEntry(cright, p_tree->GetDepth(cright),
                                 snode_[cright].best.loss_chg,
                                 timestamp++));

      ++num_leaves;  // give two and take one, as parent is no longer a leaf
    }
  }
}

void QuantileHistMaker::Builder::Update(const GHistIndexMatrix& gmat,
                                        const GHistIndexBlockMatrix& gmatb,
                                        const ColumnMatrix& column_matrix,
                                        HostDeviceVector<GradientPair>* gpair,
                                        DMatrix* p_fmat,
                                        RegTree* p_tree) {
  builder_monitor_.Start("Update");

  const std::vector<GradientPair>& gpair_h = gpair->ConstHostVector();

  spliteval_->Reset();

  this->InitData(gmat, gpair_h, *p_fmat, *p_tree);

  // Init oblivious helper.
  row_node_map_.Init(gmat.row_ptr.size() - 1, param_.max_depth);

  if (!common::ObliviousEnabled() &&
      param_.grow_policy == TrainParam::kLossGuide) {
    ExpandWithLossGuide(gmat, gmatb, column_matrix, p_fmat, p_tree, gpair_h);
  } else {
    // Enforce DepthWise for obliviousness.
    ExpandWithDepthWidth(gmat, gmatb, column_matrix, p_fmat, p_tree, gpair_h);
  }

  for (int nid = 0; nid < p_tree->param.num_nodes; ++nid) {
    p_tree->Stat(nid).loss_chg = snode_[nid].best.loss_chg;
    p_tree->Stat(nid).base_weight = snode_[nid].weight;
    p_tree->Stat(nid).sum_hess = static_cast<float>(snode_[nid].stats.sum_hess);
  }

  pruner_->Update(gpair, p_fmat, std::vector<RegTree*>{p_tree});

  builder_monitor_.Stop("Update");
}

bool QuantileHistMaker::Builder::UpdatePredictionCache(
    const DMatrix* data,
    HostDeviceVector<bst_float>* p_out_preds) {
  std::vector<bst_float>& out_preds = p_out_preds->HostVector();

  // p_last_fmat_ is a valid pointer as long as UpdatePredictionCache() is called in
  // conjunction with Update().
  if (!p_last_fmat_ || !p_last_tree_ || data != p_last_fmat_) {
    return false;
  }

  if (leaf_value_cache_.empty()) {
    leaf_value_cache_.resize(p_last_tree_->param.num_nodes,
                             std::numeric_limits<float>::infinity());
  }

  CHECK_GT(out_preds.size(), 0U);

  for (const RowSetCollection::Elem rowset : row_set_collection_) {
    if (rowset.begin != nullptr && rowset.end != nullptr) {
      int nid = rowset.node_id;
      bst_float leaf_value;
      // if a node is marked as deleted by the pruner, traverse upward to locate
      // a non-deleted leaf.
      if ((*p_last_tree_)[nid].IsDeleted()) {
        while ((*p_last_tree_)[nid].IsDeleted()) {
          nid = (*p_last_tree_)[nid].Parent();
        }
        CHECK((*p_last_tree_)[nid].IsLeaf());
      }
      leaf_value = (*p_last_tree_)[nid].LeafValue();

      for (const size_t* it = rowset.begin; it < rowset.end; ++it) {
        out_preds[*it] += leaf_value;
      }
    }
  }

  return true;
}

void QuantileHistMaker::Builder::InitData(const GHistIndexMatrix& gmat,
                                          const std::vector<GradientPair>& gpair,
                                          const DMatrix& fmat,
                                          const RegTree& tree) {
  CHECK_EQ(tree.param.num_nodes, tree.param.num_roots)
      << "ColMakerHist: can only grow new tree";
  CHECK((param_.max_depth > 0 || param_.max_leaves > 0))
      << "max_depth or max_leaves cannot be both 0 (unlimited); "
      << "at least one should be a positive quantity.";
  if (param_.grow_policy == TrainParam::kDepthWise) {
    CHECK(param_.max_depth > 0) << "max_depth cannot be 0 (unlimited) "
                                << "when grow_policy is depthwise.";
  }
  builder_monitor_.Start("InitData");
  const auto& info = fmat.Info();

  {
    // initialize the row set
    row_set_collection_.Clear();
    // clear local prediction cache
    leaf_value_cache_.clear();
    // initialize histogram collection
    uint32_t nbins = gmat.cut.row_ptr.back();
    LOG(DEBUG) << "DEBUG: nbins=" << nbins;
    hist_.Init(nbins);

    // initialize histogram builder
#pragma omp parallel
    {
      this->nthread_ = omp_get_num_threads();
    }
    hist_builder_.Init(this->nthread_, nbins);

    CHECK_EQ(info.root_index_.size(), 0U);
    std::vector<size_t>& row_indices = row_set_collection_.row_indices_;
    row_indices.resize(info.num_row_);
    auto* p_row_indices = row_indices.data();
    // mark subsample and build list of member rows

    if (param_.subsample < 1.0f) {
      std::bernoulli_distribution coin_flip(param_.subsample);
      auto& rnd = common::GlobalRandom();
      size_t j = 0;
      for (size_t i = 0; i < info.num_row_; ++i) {
        if (gpair[i].GetHess() >= 0.0f && coin_flip(rnd)) {
          p_row_indices[j++] = i;
        }
      }
      row_indices.resize(j);
    } else {
      MemStackAllocator<bool, 128> buff(this->nthread_);
      bool* p_buff = buff.Get();
      std::fill(p_buff, p_buff + this->nthread_, false);

      const size_t block_size = info.num_row_ / this->nthread_ + !!(info.num_row_ % this->nthread_);

      #pragma omp parallel num_threads(this->nthread_)
      {
        const size_t tid = omp_get_thread_num();
        const size_t ibegin = tid * block_size;
        const size_t iend = std::min(static_cast<size_t>(ibegin + block_size),
            static_cast<size_t>(info.num_row_));

        for (size_t i = ibegin; i < iend; ++i) {
          if (gpair[i].GetHess() < 0.0f) {
            p_buff[tid] = true;
            break;
          }
        }
      }

      bool has_neg_hess = false;
      for (size_t tid = 0; tid < this->nthread_; ++tid) {
        if (p_buff[tid]) {
          has_neg_hess = true;
        }
      }

      if (has_neg_hess) {
        size_t j = 0;
        for (size_t i = 0; i < info.num_row_; ++i) {
          if (gpair[i].GetHess() >= 0.0f) {
            p_row_indices[j++] = i;
          }
        }
        row_indices.resize(j);
      } else {
        #pragma omp parallel num_threads(this->nthread_)
        {
          const size_t tid = omp_get_thread_num();
          const size_t ibegin = tid * block_size;
          const size_t iend = std::min(static_cast<size_t>(ibegin + block_size),
              static_cast<size_t>(info.num_row_));
          for (size_t i = ibegin; i < iend; ++i) {
           p_row_indices[i] = i;
          }
        }
      }
    }
  }

  row_set_collection_.Init();

  {
    /* determine layout of data */
    const size_t nrow = info.num_row_;
    const size_t ncol = info.num_col_;
    const size_t nnz = info.num_nonzero_;
    // number of discrete bins for feature 0
    const uint32_t nbins_f0 = gmat.cut.row_ptr[1] - gmat.cut.row_ptr[0];
    if (nrow * ncol == nnz) {
      // dense data with zero-based indexing
      data_layout_ = kDenseDataZeroBased;
    } else if (nbins_f0 == 0 && nrow * (ncol - 1) == nnz) {
      // dense data with one-based indexing
      data_layout_ = kDenseDataOneBased;
    } else {
      // sparse data
      data_layout_ = kSparseData;
    }
  }
  {
    // store a pointer to the tree
    p_last_tree_ = &tree;
    // store a pointer to training data
    p_last_fmat_ = &fmat;
  }
  if (data_layout_ == kDenseDataOneBased) {
    column_sampler_.Init(info.num_col_, param_.colsample_bynode, param_.colsample_bylevel,
            param_.colsample_bytree, true);
  } else {
    column_sampler_.Init(info.num_col_, param_.colsample_bynode, param_.colsample_bylevel,
            param_.colsample_bytree,  false);
  }
  if (data_layout_ == kDenseDataZeroBased || data_layout_ == kDenseDataOneBased) {
    /* specialized code for dense data:
       choose the column that has a least positive number of discrete bins.
       For dense data (with no missing value),
       the sum of gradient histogram is equal to snode[nid] */
    const std::vector<uint32_t>& row_ptr = gmat.cut.row_ptr;
    const auto nfeature = static_cast<bst_uint>(row_ptr.size() - 1);
    uint32_t min_nbins_per_feature = 0;
    for (bst_uint i = 0; i < nfeature; ++i) {
      const uint32_t nbins = row_ptr[i + 1] - row_ptr[i];
      if (nbins > 0) {
        if (min_nbins_per_feature == 0 || min_nbins_per_feature > nbins) {
          min_nbins_per_feature = nbins;
          fid_least_bins_ = i;
        }
      }
    }
    CHECK_GT(min_nbins_per_feature, 0U);
  }
  {
    snode_.reserve(256);
    snode_.clear();
  }
  {
    if (param_.grow_policy == TrainParam::kLossGuide) {
      qexpand_loss_guided_.reset(new ExpandQueue(LossGuide));
    } else {
      qexpand_depth_wise_.clear();
    }
  }
  builder_monitor_.Stop("InitData");
}

void QuantileHistMaker::Builder::EvaluateSplit(const int nid,
                                               const GHistIndexMatrix& gmat,
                                               const HistCollection& hist,
                                               const DMatrix& fmat,
                                               const RegTree& tree) {
  builder_monitor_.Start("EvaluateSplit");
  // start enumeration
  const MetaInfo& info = fmat.Info();
  auto p_feature_set = column_sampler_.GetFeatureSet(tree.GetDepth(nid));
  const auto& feature_set = p_feature_set->HostVector();
  const auto nfeature = static_cast<bst_uint>(feature_set.size());
  const auto nthread = static_cast<bst_omp_uint>(this->nthread_);
  best_split_tloc_.resize(nthread);
#pragma omp parallel for schedule(static) num_threads(nthread)
  for (bst_omp_uint tid = 0; tid < nthread; ++tid) {
    best_split_tloc_[tid] = snode_[nid].best;
  }
  GHistRow node_hist = hist[nid];

#pragma omp parallel for schedule(dynamic) num_threads(nthread)
  for (bst_omp_uint i = 0; i < nfeature; ++i) {  // NOLINT(*)
    const auto feature_id = static_cast<bst_uint>(feature_set[i]);
    const auto tid = static_cast<unsigned>(omp_get_thread_num());
    const auto node_id = static_cast<bst_uint>(nid);
    // Narrow search space by dropping features that are not feasible under the
    // given set of constraints (e.g. feature interaction constraints)
    if (spliteval_->CheckFeatureConstraint(node_id, feature_id)) {
      this->EnumerateSplit(-1, gmat, node_hist, snode_[nid], info,
                           &best_split_tloc_[tid], feature_id, node_id);
      this->EnumerateSplit(+1, gmat, node_hist, snode_[nid], info,
                           &best_split_tloc_[tid], feature_id, node_id);
    }
  }
  for (unsigned tid = 0; tid < nthread; ++tid) {
    snode_[nid].best.Update(best_split_tloc_[tid]);
  }
  builder_monitor_.Stop("EvaluateSplit");
}

void QuantileHistMaker::Builder::ApplySplit(int nid,
                                            const GHistIndexMatrix& gmat,
                                            const ColumnMatrix& column_matrix,
                                            const HistCollection& hist,
                                            const DMatrix& fmat,
                                            RegTree* p_tree) {
  builder_monitor_.Start("ApplySplit");
  // TODO(hcho3): support feature sampling by levels

  /* 1. Create child nodes */
  NodeEntry& e = snode_[nid];
  bst_float left_leaf_weight =
      spliteval_->ComputeWeight(nid, e.best.left_sum) * param_.learning_rate;
  bst_float right_leaf_weight =
      spliteval_->ComputeWeight(nid, e.best.right_sum) * param_.learning_rate;
  p_tree->ExpandNode(nid, e.best.SplitIndex(), e.best.split_value,
                     e.best.DefaultLeft(), e.weight, left_leaf_weight,
                     right_leaf_weight, e.best.loss_chg, e.stats.sum_hess);

  /* 2. Categorize member rows */
  const auto nthread = static_cast<bst_omp_uint>(this->nthread_);
  row_split_tloc_.resize(nthread);
  for (bst_omp_uint i = 0; i < nthread; ++i) {
    row_split_tloc_[i].left.clear();
    row_split_tloc_[i].right.clear();
  }
  const bool default_left = (*p_tree)[nid].DefaultLeft();
  const bst_uint fid = (*p_tree)[nid].SplitIndex();
  const bst_float split_pt = (*p_tree)[nid].SplitCond();
  const uint32_t lower_bound = gmat.cut.row_ptr[fid];
  const uint32_t upper_bound = gmat.cut.row_ptr[fid + 1];
  int32_t split_cond = -1;
  // convert floating-point split_pt into corresponding bin_id
  // split_cond = -1 indicates that split_pt is less than all known cut points
  CHECK_LT(upper_bound,
           static_cast<uint32_t>(std::numeric_limits<int32_t>::max()));
  for (uint32_t i = lower_bound; i < upper_bound; ++i) {
    if (split_pt == gmat.cut.cut[i]) {
      split_cond = static_cast<int32_t>(i);
    }
  }

  LOG(DEBUG) << "DEBUG_RAW: split_cond[" << nid << "] = " << split_cond;

  const auto& rowset = row_set_collection_[nid];

  Column column = column_matrix.GetColumn(fid);
  if (column.GetType() == xgboost::common::kDenseColumn) {
    ApplySplitDenseData(rowset, gmat, &row_split_tloc_, column, split_cond,
                        default_left);
  } else {
    ApplySplitSparseData(rowset, gmat, &row_split_tloc_, column, lower_bound,
                         upper_bound, split_cond, default_left);
  }

  row_set_collection_.AddSplit(
      nid, row_split_tloc_, (*p_tree)[nid].LeftChild(), (*p_tree)[nid].RightChild());
  builder_monitor_.Stop("ApplySplit");
}

void QuantileHistMaker::Builder::ApplySplitDenseData(
    const RowSetCollection::Elem rowset,
    const GHistIndexMatrix& gmat,
    std::vector<RowSetCollection::Split>* p_row_split_tloc,
    const Column& column,
    bst_int split_cond,
    bool default_left) {
  std::vector<RowSetCollection::Split>& row_split_tloc = *p_row_split_tloc;
  constexpr int kUnroll = 8;  // loop unrolling factor
  const size_t nrows = rowset.end - rowset.begin;
  const size_t rest = nrows % kUnroll;

#pragma omp parallel for num_threads(nthread_) schedule(static)
  for (bst_omp_uint i = 0; i < nrows - rest; i += kUnroll) {
    const bst_uint tid = omp_get_thread_num();
    auto& left = row_split_tloc[tid].left;
    auto& right = row_split_tloc[tid].right;
    size_t rid[kUnroll];
    uint32_t rbin[kUnroll];
    for (int k = 0; k < kUnroll; ++k) {
      rid[k] = rowset.begin[i + k];
    }
    for (int k = 0; k < kUnroll; ++k) {
      rbin[k] = column.GetFeatureBinIdx(rid[k]);
    }
    for (int k = 0; k < kUnroll; ++k) {                      // NOLINT
      if (rbin[k] == std::numeric_limits<uint32_t>::max()) {  // missing value
        if (default_left) {
          left.push_back(rid[k]);
        } else {
          right.push_back(rid[k]);
        }
      } else {
        if (static_cast<int32_t>(rbin[k] + column.GetBaseIdx()) <= split_cond) {
          left.push_back(rid[k]);
        } else {
          right.push_back(rid[k]);
        }
      }
    }
  }
  for (size_t i = nrows - rest; i < nrows; ++i) {
    auto& left = row_split_tloc[nthread_-1].left;
    auto& right = row_split_tloc[nthread_-1].right;
    const size_t rid = rowset.begin[i];
    const uint32_t rbin = column.GetFeatureBinIdx(rid);
    if (rbin == std::numeric_limits<uint32_t>::max()) {  // missing value
      if (default_left) {
        left.push_back(rid);
      } else {
        right.push_back(rid);
      }
    } else {
      if (static_cast<int32_t>(rbin + column.GetBaseIdx()) <= split_cond) {
        left.push_back(rid);
      } else {
        right.push_back(rid);
      }
    }
  }
}

void QuantileHistMaker::Builder::ApplySplitSparseData(
    const RowSetCollection::Elem rowset,
    const GHistIndexMatrix& gmat,
    std::vector<RowSetCollection::Split>* p_row_split_tloc,
    const Column& column,
    bst_uint lower_bound,
    bst_uint upper_bound,
    bst_int split_cond,
    bool default_left) {
  std::vector<RowSetCollection::Split>& row_split_tloc = *p_row_split_tloc;
  const size_t nrows = rowset.end - rowset.begin;

#pragma omp parallel num_threads(nthread_)
  {
    const auto tid = static_cast<size_t>(omp_get_thread_num());
    const size_t ibegin = tid * nrows / nthread_;
    const size_t iend = (tid + 1) * nrows / nthread_;
    if (ibegin < iend) {  // ensure that [ibegin, iend) is nonempty range
      // search first nonzero row with index >= rowset[ibegin]
      const size_t* p = std::lower_bound(column.GetRowData(),
                                         column.GetRowData() + column.Size(),
                                         rowset.begin[ibegin]);

      auto& left = row_split_tloc[tid].left;
      auto& right = row_split_tloc[tid].right;
      if (p != column.GetRowData() + column.Size() && *p <= rowset.begin[iend - 1]) {
        size_t cursor = p - column.GetRowData();

        for (size_t i = ibegin; i < iend; ++i) {
          const size_t rid = rowset.begin[i];
          while (cursor < column.Size()
                 && column.GetRowIdx(cursor) < rid
                 && column.GetRowIdx(cursor) <= rowset.begin[iend - 1]) {
            ++cursor;
          }
          if (cursor < column.Size() && column.GetRowIdx(cursor) == rid) {
            const uint32_t rbin = column.GetFeatureBinIdx(cursor);
            if (static_cast<int32_t>(rbin + column.GetBaseIdx()) <= split_cond) {
              left.push_back(rid);
            } else {
              right.push_back(rid);
            }
            ++cursor;
          } else {
            // missing value
            if (default_left) {
              left.push_back(rid);
            } else {
              right.push_back(rid);
            }
          }
        }
      } else {  // all rows in [ibegin, iend) have missing values
        if (default_left) {
          for (size_t i = ibegin; i < iend; ++i) {
            const size_t rid = rowset.begin[i];
            left.push_back(rid);
          }
        } else {
          for (size_t i = ibegin; i < iend; ++i) {
            const size_t rid = rowset.begin[i];
            right.push_back(rid);
          }
        }
      }
    }
  }
}

void QuantileHistMaker::Builder::InitNewNode(int nid,
                                             const GHistIndexMatrix& gmat,
                                             const std::vector<GradientPair>& gpair,
                                             const DMatrix& fmat,
                                             const RegTree& tree) {
  builder_monitor_.Start("InitNewNode");
  {
    snode_.resize(tree.param.num_nodes, NodeEntry(param_));
  }

  {
    auto& stats = snode_[nid].stats;
    GHistRow hist = hist_[nid];
    if (tree[nid].IsRoot()) {
      if (data_layout_ == kDenseDataZeroBased || data_layout_ == kDenseDataOneBased) {
        const std::vector<uint32_t>& row_ptr = gmat.cut.row_ptr;
        const uint32_t ibegin = row_ptr[fid_least_bins_];
        const uint32_t iend = row_ptr[fid_least_bins_ + 1];
        auto begin = hist.data();
        for (uint32_t i = ibegin; i < iend; ++i) {
          const GradStats et = begin[i];
          stats.Add(et.sum_grad, et.sum_hess);
        }
      } else {
        const RowSetCollection::Elem e = row_set_collection_[nid];
        for (const size_t* it = e.begin; it < e.end; ++it) {
          stats.Add(gpair[*it]);
        }
      }
      histred_.Allreduce(&snode_[nid].stats, 1);
    } else {
      int parent_id = tree[nid].Parent();
      if (tree[nid].IsLeftChild()) {
        snode_[nid].stats = snode_[parent_id].best.left_sum;
      } else {
        snode_[nid].stats = snode_[parent_id].best.right_sum;
      }
    }
  }

  // calculating the weights
  {
    bst_uint parentid = tree[nid].Parent();
    snode_[nid].weight = static_cast<float>(
            spliteval_->ComputeWeight(parentid, snode_[nid].stats));
    snode_[nid].root_gain = static_cast<float>(
            spliteval_->ComputeScore(parentid, snode_[nid].stats, snode_[nid].weight));
  }
  builder_monitor_.Stop("InitNewNode");
}

// enumerate the split values of specific feature
void QuantileHistMaker::Builder::EnumerateSplit(int d_step,
                                                const GHistIndexMatrix& gmat,
                                                const GHistRow& hist,
                                                const NodeEntry& snode,
                                                const MetaInfo& info,
                                                SplitEntry* p_best,
                                                bst_uint fid,
                                                bst_uint nodeID) {
  CHECK(d_step == +1 || d_step == -1);

  // aliases
  const std::vector<uint32_t>& cut_ptr = gmat.cut.row_ptr;
  const std::vector<bst_float>& cut_val = gmat.cut.cut;

  // statistics on both sides of split
  GradStats c;
  GradStats e;
  // best split so far
  SplitEntry best;

  // bin boundaries
  CHECK_LE(cut_ptr[fid],
           static_cast<uint32_t>(std::numeric_limits<int32_t>::max()));
  CHECK_LE(cut_ptr[fid + 1],
           static_cast<uint32_t>(std::numeric_limits<int32_t>::max()));
  // imin: index (offset) of the minimum value for feature fid
  //       need this for backward enumeration
  const auto imin = static_cast<int32_t>(cut_ptr[fid]);
  // ibegin, iend: smallest/largest cut points for feature fid
  // use int to allow for value -1
  int32_t ibegin, iend;
  if (d_step > 0) {
    ibegin = static_cast<int32_t>(cut_ptr[fid]);
    iend = static_cast<int32_t>(cut_ptr[fid + 1]);
  } else {
    ibegin = static_cast<int32_t>(cut_ptr[fid + 1]) - 1;
    iend = static_cast<int32_t>(cut_ptr[fid]) - 1;
  }

  for (int32_t i = ibegin; i != iend; i += d_step) {
    // start working
    // try to find a split
    e.Add(hist[i].GetGrad(), hist[i].GetHess());
    if (e.sum_hess >= param_.min_child_weight) {
      c.SetSubstract(snode.stats, e);
      if (c.sum_hess >= param_.min_child_weight) {
        bst_float loss_chg;
        bst_float split_pt;
        if (d_step > 0) {
          // forward enumeration: split at right bound of each bin
          loss_chg = static_cast<bst_float>(
              spliteval_->ComputeSplitScore(nodeID, fid, e, c) -
              snode.root_gain);
          split_pt = cut_val[i];
          best.Update(loss_chg, fid, split_pt, d_step == -1, e, c);
        } else {
          // backward enumeration: split at left bound of each bin
          loss_chg = static_cast<bst_float>(
              spliteval_->ComputeSplitScore(nodeID, fid, c, e) -
              snode.root_gain);
          if (i == imin) {
            // for leftmost bin, left bound is the smallest feature value
            split_pt = gmat.cut.min_val[fid];
          } else {
            split_pt = cut_val[i - 1];
          }
          best.Update(loss_chg, fid, split_pt, d_step == -1, c, e);
        }
      }
    }
  }
  p_best->Update(best);
}

void QuantileHistMaker::Builder::BuildLocalHistogramsLevelWise(
    int* starting_index, int* sync_count, const GHistIndexMatrix& gmat,
    const GHistIndexBlockMatrix& gmatb, RegTree* p_tree,
    const std::vector<GradientPair>& gpair_h) {
  builder_monitor_.Start("BuildLocalHistogramsLevelWise");

  LOG(DEBUG) << "DEBUG: begin " << __func__;

  // pre-allocate spaces
  std::vector<int> node_ids;
  int depth = -1;
  size_t level_width = 0;
  for (auto const& entry : qexpand_depth_wise_) {
    DCHECK(depth == -1 || depth == entry.depth);
    depth = entry.depth;
    hist_.AddHistRow(entry.nid);
    LOG(DEBUG) << "DEBUG: add nid=" << entry.nid;
    node_ids.push_back(entry.nid);
    *starting_index = std::min(*starting_index, entry.nid);
    (*sync_count)++;
    level_width++;
  }

  std::vector<HistCollection> hists(this->nthread_);
  for (auto& hist : hists) {
    hist.Init(hist_.nbins(), level_width);
  }

  const uint32_t* index = gmat.index.data();
  const size_t* row_ptr =  gmat.row_ptr.data();
  const auto nrows = gmat.row_ptr.size() - 1;

  // The subtraction trick does not benefit obliviousness.
  // O(n_cols * n_rows * O(`oaccess`)).
  int last_offset = -1;
#pragma omp parallel for schedule(static) num_threads(this->nthread_)
  for (size_t row_idx = 0; row_idx < nrows; ++row_idx) {
    const uint32_t tid = omp_get_thread_num();
    const size_t icol_start = row_ptr[row_idx];
    const size_t icol_end = row_ptr[row_idx + 1];
    std::vector<tree::GradStats> delta_stats(hist_.nbins(), tree::GradStats{0, 0});

		int nbins = static_cast<uint32_t>(param_.max_bin) - 1;    
		// TODO: This loop is probably not oblivious if input data was in LibSVM format (i.e. sparse)
		for (size_t j = icol_start; j < icol_end; ++j) {
			const uint32_t idx_bin = index[j];
			CHECK(idx_bin < delta_stats.size())
				<< "idx_bin=" << idx_bin << ", nbins=" << delta_stats.size();
			size_t start_idx = (idx_bin / nbins) * nbins;
			auto grad = ObliviousArrayAccess(delta_stats.data() + start_idx, idx_bin - start_idx, nbins); 
			grad.Add(gpair_h[row_idx]);
			ObliviousArrayAssign(delta_stats.data() + start_idx, idx_bin - start_idx, nbins, grad);
		}

		/*
     *for (size_t j = icol_start; j < icol_end; ++j) {
     *  const uint32_t idx_bin = index[j];
     *  CHECK(idx_bin < delta_stats.size())
     *    << "idx_bin=" << idx_bin << ", nbins=" << delta_stats.size();
     *  auto grad = ObliviousArrayAccess(delta_stats.data(), idx_bin, delta_stats.size());
     *  grad.Add(gpair_h[row_idx]);
     *  ObliviousArrayAssign(delta_stats.data(), idx_bin, delta_stats.size(), grad);
     *}
		 */
    const int target_nid = row_node_map_.GetRowTarget(row_idx, depth);
    CHECK(target_nid >= 0 && target_nid < p_tree->param.num_nodes)
      << "Bad target_nid: " << target_nid;
    std::vector<tree::GradStats> previous_stats(delta_stats.size(), tree::GradStats{0, 0});
    auto range = GetLevelNodeRange(target_nid);
    const size_t level_idx = target_nid - range.first;

    // For debug.
    CHECK(last_offset == -1 || range.first == last_offset)
        << "range.first=" << range.first << ", last_offset=" << last_offset;
    last_offset = range.first;

    // oaccess in range [level_begin_nid, level_end_nid]
    ObliviousArrayAccessBytes(
        previous_stats.data(), hists[tid][0].data(),
        previous_stats.size() * sizeof(decltype(previous_stats)::value_type),
        level_idx, level_width);
    // Add.
    for (size_t bin_idx = 0; bin_idx < delta_stats.size(); ++bin_idx) {
      delta_stats[bin_idx].Add(previous_stats[bin_idx]);
    }
    // oaccess in range [level_begin_nid, level_end_nid]
    ObliviousArrayAssignBytes(
        hists[tid][0].data(), delta_stats.data(),
        delta_stats.size() * sizeof(decltype(delta_stats)::value_type),
        level_idx, level_width);
  }

  // Merge threading results.
  for (const auto& hist : hists) {
    for (size_t level_idx = 0; level_idx < level_width; ++level_idx) {
      const size_t nid = level_idx + last_offset;
      for (size_t bin_idx = 0; bin_idx < hist_.nbins(); ++bin_idx) {
        hist_[nid][bin_idx].Add(hist[level_idx][bin_idx]);
      }
    }
  }

  builder_monitor_.Stop("BuildLocalHistogramsLevelWise");
  LOG(DEBUG) << "DEBUG: end " << __func__;
}

XGBOOST_REGISTER_TREE_UPDATER(FastHistMaker, "grow_fast_histmaker")
.describe("(Deprecated, use grow_quantile_histmaker instead.)"
          " Grow tree using quantized histogram.")
.set_body(
    []() {
      LOG(WARNING) << "grow_fast_histmaker is deprecated, "
                   << "use grow_quantile_histmaker instead.";
      return new QuantileHistMaker();
    });

XGBOOST_REGISTER_TREE_UPDATER(QuantileHistMaker, "grow_quantile_histmaker")
.describe("Grow tree using quantized histogram.")
.set_body(
    []() {
      return new QuantileHistMaker();
    });

}  // namespace tree
}  // namespace xgboost
