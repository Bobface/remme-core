# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: certificate.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
from google.protobuf import descriptor_pb2
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='certificate.proto',
  package='',
  syntax='proto3',
  serialized_pb=_b('\n\x11\x63\x65rtificate.proto\"4\n\x11\x43\x65rtificateMethod\"\x1f\n\x06Method\x12\t\n\x05STORE\x10\x00\x12\n\n\x06REVOKE\x10\x01\"~\n\x15NewCertificatePayload\x12\x17\n\x0f\x63\x65rtificate_raw\x18\x01 \x01(\t\x12\x15\n\rsignature_rem\x18\x02 \x01(\t\x12\x15\n\rsignature_crt\x18\x03 \x01(\t\x12\x1e\n\x16\x63\x65rt_signer_public_key\x18\x04 \x01(\t\"+\n\x18RevokeCertificatePayload\x12\x0f\n\x07\x61\x64\x64ress\x18\x01 \x01(\t\"B\n\x12\x43\x65rtificateStorage\x12\x0c\n\x04hash\x18\x01 \x01(\t\x12\r\n\x05owner\x18\x02 \x01(\t\x12\x0f\n\x07revoked\x18\x03 \x01(\x08\x62\x06proto3')
)



_CERTIFICATEMETHOD_METHOD = _descriptor.EnumDescriptor(
  name='Method',
  full_name='CertificateMethod.Method',
  filename=None,
  file=DESCRIPTOR,
  values=[
    _descriptor.EnumValueDescriptor(
      name='STORE', index=0, number=0,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='REVOKE', index=1, number=1,
      options=None,
      type=None),
  ],
  containing_type=None,
  options=None,
  serialized_start=42,
  serialized_end=73,
)
_sym_db.RegisterEnumDescriptor(_CERTIFICATEMETHOD_METHOD)


_CERTIFICATEMETHOD = _descriptor.Descriptor(
  name='CertificateMethod',
  full_name='CertificateMethod',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
    _CERTIFICATEMETHOD_METHOD,
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=21,
  serialized_end=73,
)


_NEWCERTIFICATEPAYLOAD = _descriptor.Descriptor(
  name='NewCertificatePayload',
  full_name='NewCertificatePayload',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='certificate_raw', full_name='NewCertificatePayload.certificate_raw', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='signature_rem', full_name='NewCertificatePayload.signature_rem', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='signature_crt', full_name='NewCertificatePayload.signature_crt', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='cert_signer_public_key', full_name='NewCertificatePayload.cert_signer_public_key', index=3,
      number=4, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=75,
  serialized_end=201,
)


_REVOKECERTIFICATEPAYLOAD = _descriptor.Descriptor(
  name='RevokeCertificatePayload',
  full_name='RevokeCertificatePayload',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='address', full_name='RevokeCertificatePayload.address', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=203,
  serialized_end=246,
)


_CERTIFICATESTORAGE = _descriptor.Descriptor(
  name='CertificateStorage',
  full_name='CertificateStorage',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='hash', full_name='CertificateStorage.hash', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='owner', full_name='CertificateStorage.owner', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='revoked', full_name='CertificateStorage.revoked', index=2,
      number=3, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=248,
  serialized_end=314,
)

_CERTIFICATEMETHOD_METHOD.containing_type = _CERTIFICATEMETHOD
DESCRIPTOR.message_types_by_name['CertificateMethod'] = _CERTIFICATEMETHOD
DESCRIPTOR.message_types_by_name['NewCertificatePayload'] = _NEWCERTIFICATEPAYLOAD
DESCRIPTOR.message_types_by_name['RevokeCertificatePayload'] = _REVOKECERTIFICATEPAYLOAD
DESCRIPTOR.message_types_by_name['CertificateStorage'] = _CERTIFICATESTORAGE
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

CertificateMethod = _reflection.GeneratedProtocolMessageType('CertificateMethod', (_message.Message,), dict(
  DESCRIPTOR = _CERTIFICATEMETHOD,
  __module__ = 'certificate_pb2'
  # @@protoc_insertion_point(class_scope:CertificateMethod)
  ))
_sym_db.RegisterMessage(CertificateMethod)

NewCertificatePayload = _reflection.GeneratedProtocolMessageType('NewCertificatePayload', (_message.Message,), dict(
  DESCRIPTOR = _NEWCERTIFICATEPAYLOAD,
  __module__ = 'certificate_pb2'
  # @@protoc_insertion_point(class_scope:NewCertificatePayload)
  ))
_sym_db.RegisterMessage(NewCertificatePayload)

RevokeCertificatePayload = _reflection.GeneratedProtocolMessageType('RevokeCertificatePayload', (_message.Message,), dict(
  DESCRIPTOR = _REVOKECERTIFICATEPAYLOAD,
  __module__ = 'certificate_pb2'
  # @@protoc_insertion_point(class_scope:RevokeCertificatePayload)
  ))
_sym_db.RegisterMessage(RevokeCertificatePayload)

CertificateStorage = _reflection.GeneratedProtocolMessageType('CertificateStorage', (_message.Message,), dict(
  DESCRIPTOR = _CERTIFICATESTORAGE,
  __module__ = 'certificate_pb2'
  # @@protoc_insertion_point(class_scope:CertificateStorage)
  ))
_sym_db.RegisterMessage(CertificateStorage)


# @@protoc_insertion_point(module_scope)
