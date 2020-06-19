import securexgboost as xgb

# Start orchestrator
xgb.serve(all_users=["user1"], nodes=["127.0.0.1"], port=50052)
