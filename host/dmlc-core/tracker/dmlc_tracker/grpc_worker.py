'''
Script run by worker machines to start listening for RPCs.
gRPC Worker API

usage - python3 grpc_worker.py <PORT> <PATH_TO_DATA> <PATH_TO_MODEL>
'''
from concurrent import futures

import _credentials

import fxgb_pb2
import fxgb_pb2_grpc
import grpc

import ctypes
import sys

import pandas as pd
import xgboost as xgb


def get_dmlc_vars(env):
    '''
    Returns list of strings representing DMLC variables needed for rabit.
    Parsed in allreduce_base.cc from '<name>=<value>' format.
    
    Param:
        env - Env protobuf
    
    Return:
        list containing DMLC variables
    '''
    temp = [
        'DMLC_TRACKER_URI=' + env.DMLC_TRACKER_URI,
        'DMLC_TRACKER_PORT=' + str(env.DMLC_TRACKER_PORT),
        'DMLC_ROLE=' + env.DMLC_ROLE,
        'DMLC_NODE_HOST=' + env.DMLC_NODE_HOST,
        'DMLC_NUM_WORKER=' + str(env.DMLC_NUM_WORKER),
        'DMLC_NUM_SERVER=' + str(env.DMLC_NUM_SERVER),
    ]
    # Python strings are unicode, but C strings are bytes, so we must convert to bytes.
    return [bytes(s, 'utf-8') for s in temp]

def get_train_request_field_or_none(train_request, field):
    return getattr(train_request, field) if train_request.HasField(field) else None

def get_train_params(train_request):
    '''
    Returns (param, num_round) from parsing TrainRequest protobuf.
    '''
    fields = [
        'eta',
        'gamma',
        'max_depth',
        'min_child_weight',
        'max_delta_step',
        'subsample',
        'colsample_bytree',
        'colsample_bylevel',
        'colsample_bynode',
        'lambda',
        'alpha',
        'tree_method',
        'sketch_eps',
        'scale_pos_weight',
        'updater',
        'refresh_leaf', 
        'process_type', 
        'grow_policy', 
        'max_leaves',
        'max_bin',
        'predictor',
        'num_parallel_tree',
        'objective',
        'base_score',
        'eval_metric',
    ]
    param = {}
    for field in fields:
        val = get_train_request_field_or_none(train_request, field)
        if val:
            param[field] = val
    num_round = train_request.num_round if train_request.HasField('num_round') else 10
    return param, num_round

class FederatedXGBoostServicer():
    ''' gRPC servicer class which implements worker machine RPCs API. '''

    def __init__(self, port, data_path, model_path):
        self.model = None
        self.dmlc_vars = None
        self.port = port
        self.data_path = data_path
        self.model_path = model_path
        print("Started up FXGB worker. Now listening on port %s for RPC to start job." % self.port)

    def Init(self, init_request, context):
        '''
        Initializes rabit and environment variables.
        When worker receives this RPC, it can accept or reject the federated training session.

        Params:
            init_request - InitRequest proto containing DMLC variables to set up node communication with tracker
            context - RPC context. Contains metadata about the connection

        Return:
            WorkerResponse proto (confirmation of initializatison success or failure).
        '''
        print('Request from aggregator [%s] to start federated training session:' % context.peer())
        accept_job = None
        while accept_job not in {'Y', 'N'}:
            print("Please enter 'Y' to confirm or 'N' to reject.")
            accept_job = input("Join session? [Y/N]: ")
        if accept_job == 'Y':
            self.dmlc_vars = get_dmlc_vars(request.dmlc_vars)
            return fxgb_pb2.WorkerResponse(success=True)
        else:
            return fxgb_pb2.WorkerResponse(success=False)

    def Train(self, train_request, context):
        '''
        Starts distributed training.

        Params:
            train_request - TrainRequest proto containing XGBoost parameters for training
            context - RPC context containing metadata about the connection

        Return:
            WorkerResponse proto (confirmation of training success or failure).
        '''
        try:
            print('Request from aggregator [%s] to start federated training session:' % context.peer())
            xgb.rabit.init(self.dmlc_vars)
            print('Loading dataset...')
            dataset = pd.read_csv(self.data_path, delimiter=',', header=None)
            data, label = dataset.iloc[:, 1:], dataset.iloc[:, 0]
            dtrain = xgb.DMatrix(data, label=label)
            print('Dataset loaded.')
            param, num_round = get_train_params(request)
            print('Starting training...')
            model = xgb.train(param, dtrain, num_round)
            print('Training finished.')
            model.save_model(self.model_path)
            print('Model saved.')
            xgb.rabit.finalize()
            return fxgb_pb2.WorkerResponse(success=True)
        except:
            return fxgb_pb2.WorkerResponse(success=False)


# Start gRPC server listening on port 'port'
def start_worker(port, data_path, model_path):
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=1))
    fxgb_pb2_grpc.add_FXGBWorkerServicer_to_server(FederatedXGBoostServicer(port, data_path, model_path), server)
    server_credentials = grpc.ssl_server_credentials(
        ((_credentials.SERVER_CERTIFICATE_KEY, _credentials.SERVER_CERTIFICATE),))
    server.add_secure_port('[::]:' + port, server_credentials)
    server.start()
    server.wait_for_termination()


if __name__ == '__main__':
    assert len(sys.argv) == 4, "usage - python3 grpc_worker.py <PORT> <PATH TO DATA> <PATH TO SAVE MODEL>"
    start_worker(sys.argv[1], sys.argv[2], sys.argv[3])
