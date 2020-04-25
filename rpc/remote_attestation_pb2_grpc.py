# Generated by the gRPC Python protocol compiler plugin. DO NOT EDIT!
import grpc

import remote_attestation_pb2 as remote__attestation__pb2


class RemoteAttestationStub(object):
  """Interface exported by the server.
  """

  def __init__(self, channel):
    """Constructor.

    Args:
      channel: A grpc.Channel.
    """
    self.rpc_get_remote_report_with_pubkey = channel.unary_unary(
        '/remote_attestation.RemoteAttestation/rpc_get_remote_report_with_pubkey',
        request_serializer=remote__attestation__pb2.Status.SerializeToString,
        response_deserializer=remote__attestation__pb2.Report.FromString,
        )
    self.rpc_add_client_key = channel.unary_unary(
        '/remote_attestation.RemoteAttestation/rpc_add_client_key',
        request_serializer=remote__attestation__pb2.DataMetadata.SerializeToString,
        response_deserializer=remote__attestation__pb2.Status.FromString,
        )
    self.rpc_add_client_key_with_certificate = channel.unary_unary(
        '/remote_attestation.RemoteAttestation/rpc_add_client_key_with_certificate',
        request_serializer=remote__attestation__pb2.DataMetadata.SerializeToString,
        response_deserializer=remote__attestation__pb2.Status.FromString,
        )
    self.rpc_XGDMatrixCreateFromEncryptedFile = channel.unary_unary(
        '/remote_attestation.RemoteAttestation/rpc_XGDMatrixCreateFromEncryptedFile',
        request_serializer=remote__attestation__pb2.DMatrixAttrs.SerializeToString,
        response_deserializer=remote__attestation__pb2.Name.FromString,
        )
    self.rpc_XGBoosterCreate = channel.unary_unary(
        '/remote_attestation.RemoteAttestation/rpc_XGBoosterCreate',
        request_serializer=remote__attestation__pb2.BoosterAttrs.SerializeToString,
        response_deserializer=remote__attestation__pb2.Name.FromString,
        )
    self.rpc_XGBoosterSetParam = channel.unary_unary(
        '/remote_attestation.RemoteAttestation/rpc_XGBoosterSetParam',
        request_serializer=remote__attestation__pb2.BoosterParam.SerializeToString,
        response_deserializer=remote__attestation__pb2.Status.FromString,
        )
    self.rpc_XGBoosterUpdateOneIter = channel.unary_unary(
        '/remote_attestation.RemoteAttestation/rpc_XGBoosterUpdateOneIter',
        request_serializer=remote__attestation__pb2.BoosterUpdateParams.SerializeToString,
        response_deserializer=remote__attestation__pb2.Status.FromString,
        )
    self.SignalStartCluster = channel.unary_unary(
        '/remote_attestation.RemoteAttestation/SignalStartCluster',
        request_serializer=remote__attestation__pb2.ClusterParams.SerializeToString,
        response_deserializer=remote__attestation__pb2.Status.FromString,
        )
    self.rpc_XGBoosterPredict = channel.unary_unary(
        '/remote_attestation.RemoteAttestation/rpc_XGBoosterPredict',
        request_serializer=remote__attestation__pb2.PredictParams.SerializeToString,
        response_deserializer=remote__attestation__pb2.Predictions.FromString,
        )


class RemoteAttestationServicer(object):
  """Interface exported by the server.
  """

  def rpc_get_remote_report_with_pubkey(self, request, context):
    """Get attestation report
    Status is a just a dummy argument and won't be used by the server
    """
    context.set_code(grpc.StatusCode.UNIMPLEMENTED)
    context.set_details('Method not implemented!')
    raise NotImplementedError('Method not implemented!')

  def rpc_add_client_key(self, request, context):
    """Send symmetric key encrypted with enclave public key, signature
    """
    context.set_code(grpc.StatusCode.UNIMPLEMENTED)
    context.set_details('Method not implemented!')
    raise NotImplementedError('Method not implemented!')

  def rpc_add_client_key_with_certificate(self, request, context):
    """Send symmetric key encrypted with enclave public key, signature, certificate
    """
    context.set_code(grpc.StatusCode.UNIMPLEMENTED)
    context.set_details('Method not implemented!')
    raise NotImplementedError('Method not implemented!')

  def rpc_XGDMatrixCreateFromEncryptedFile(self, request, context):
    """Send params of a DMatrix to the server for initialization
    Returns the name assigned to this DMatrix
    """
    context.set_code(grpc.StatusCode.UNIMPLEMENTED)
    context.set_details('Method not implemented!')
    raise NotImplementedError('Method not implemented!')

  def rpc_XGBoosterCreate(self, request, context):
    """Send params of a Booster to the server for initialization 
    Returns the name assigned to this booster
    """
    context.set_code(grpc.StatusCode.UNIMPLEMENTED)
    context.set_details('Method not implemented!')
    raise NotImplementedError('Method not implemented!')

  def rpc_XGBoosterSetParam(self, request, context):
    """Set booster parameters
    """
    context.set_code(grpc.StatusCode.UNIMPLEMENTED)
    context.set_details('Method not implemented!')
    raise NotImplementedError('Method not implemented!')

  def rpc_XGBoosterUpdateOneIter(self, request, context):
    """Update the booster for one round
    rpc BoosterUpdate(BoosterUpdateParams) returns (Status) {}

    Update the booster for one round
    """
    context.set_code(grpc.StatusCode.UNIMPLEMENTED)
    context.set_details('Method not implemented!')
    raise NotImplementedError('Method not implemented!')

  def SignalStartCluster(self, request, context):
    """Signal to RPC server that the client is ready for distributed training
    """
    context.set_code(grpc.StatusCode.UNIMPLEMENTED)
    context.set_details('Method not implemented!')
    raise NotImplementedError('Method not implemented!')

  def rpc_XGBoosterPredict(self, request, context):
    """Run predictions
    rpc Predict(PredictParams) returns (Predictions) {}

    Run predictions
    """
    context.set_code(grpc.StatusCode.UNIMPLEMENTED)
    context.set_details('Method not implemented!')
    raise NotImplementedError('Method not implemented!')


def add_RemoteAttestationServicer_to_server(servicer, server):
  rpc_method_handlers = {
      'rpc_get_remote_report_with_pubkey': grpc.unary_unary_rpc_method_handler(
          servicer.rpc_get_remote_report_with_pubkey,
          request_deserializer=remote__attestation__pb2.Status.FromString,
          response_serializer=remote__attestation__pb2.Report.SerializeToString,
      ),
      'rpc_add_client_key': grpc.unary_unary_rpc_method_handler(
          servicer.rpc_add_client_key,
          request_deserializer=remote__attestation__pb2.DataMetadata.FromString,
          response_serializer=remote__attestation__pb2.Status.SerializeToString,
      ),
      'rpc_add_client_key_with_certificate': grpc.unary_unary_rpc_method_handler(
          servicer.rpc_add_client_key_with_certificate,
          request_deserializer=remote__attestation__pb2.DataMetadata.FromString,
          response_serializer=remote__attestation__pb2.Status.SerializeToString,
      ),
      'rpc_XGDMatrixCreateFromEncryptedFile': grpc.unary_unary_rpc_method_handler(
          servicer.rpc_XGDMatrixCreateFromEncryptedFile,
          request_deserializer=remote__attestation__pb2.DMatrixAttrs.FromString,
          response_serializer=remote__attestation__pb2.Name.SerializeToString,
      ),
      'rpc_XGBoosterCreate': grpc.unary_unary_rpc_method_handler(
          servicer.rpc_XGBoosterCreate,
          request_deserializer=remote__attestation__pb2.BoosterAttrs.FromString,
          response_serializer=remote__attestation__pb2.Name.SerializeToString,
      ),
      'rpc_XGBoosterSetParam': grpc.unary_unary_rpc_method_handler(
          servicer.rpc_XGBoosterSetParam,
          request_deserializer=remote__attestation__pb2.BoosterParam.FromString,
          response_serializer=remote__attestation__pb2.Status.SerializeToString,
      ),
      'rpc_XGBoosterUpdateOneIter': grpc.unary_unary_rpc_method_handler(
          servicer.rpc_XGBoosterUpdateOneIter,
          request_deserializer=remote__attestation__pb2.BoosterUpdateParams.FromString,
          response_serializer=remote__attestation__pb2.Status.SerializeToString,
      ),
      'SignalStartCluster': grpc.unary_unary_rpc_method_handler(
          servicer.SignalStartCluster,
          request_deserializer=remote__attestation__pb2.ClusterParams.FromString,
          response_serializer=remote__attestation__pb2.Status.SerializeToString,
      ),
      'rpc_XGBoosterPredict': grpc.unary_unary_rpc_method_handler(
          servicer.rpc_XGBoosterPredict,
          request_deserializer=remote__attestation__pb2.PredictParams.FromString,
          response_serializer=remote__attestation__pb2.Predictions.SerializeToString,
      ),
  }
  generic_handler = grpc.method_handlers_generic_handler(
      'remote_attestation.RemoteAttestation', rpc_method_handlers)
  server.add_generic_rpc_handlers((generic_handler,))
