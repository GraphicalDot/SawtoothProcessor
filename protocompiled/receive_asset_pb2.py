# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: receive_asset.proto

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
  name='receive_asset.proto',
  package='',
  syntax='proto3',
  serialized_pb=_b('\n\x13receive_asset.proto\"\x99\x03\n\x0cReceiveAsset\x12\x0c\n\x04_id_\x18\x0e \x01(\t\x12\x0c\n\x04time\x18\x01 \x01(\r\x12\x12\n\nindiantime\x18\x02 \x01(\t\x12\x0b\n\x03idx\x18\x03 \x01(\r\x12\x1e\n\x16\x61t_which_asset_expires\x18\x05 \x01(\x02\x12\x10\n\x08org_name\x18\x06 \x01(\t\x12\x13\n\x0borg_address\x18\x07 \x01(\t\x12\x10\n\x08org_role\x18\x08 \x01(\t\x12\x34\n\x15receive_asset_details\x18\t \x01(\x0b\x32\x15.CReceiveAssetDetails\x12\x16\n\x0e\x63hild_zero_pub\x18\n \x01(\t\x12\x14\n\x0csigned_nonce\x18\x0b \x01(\t\x12\r\n\x05nonce\x18\x0c \x01(\r\x12\x12\n\nnonce_hash\x18\r \x01(\t\x12\x0e\n\x06public\x18\x0f \x01(\t\x12\x18\n\x10unique_code_hash\x18\x10 \x01(\t\x12\x1d\n\x15\x65ncrypted_unique_code\x18\x11 \x01(\t\x12#\n\x1b\x65ncrypted_admin_unique_code\x18\x12 \x01(\t\"9\n\x14\x43ReceiveAssetDetails\x12\x0c\n\x04name\x18\x01 \x01(\t\x12\x13\n\x0b\x64\x65scription\x18\x05 \x01(\tb\x06proto3')
)




_RECEIVEASSET = _descriptor.Descriptor(
  name='ReceiveAsset',
  full_name='ReceiveAsset',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='_id_', full_name='ReceiveAsset._id_', index=0,
      number=14, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='time', full_name='ReceiveAsset.time', index=1,
      number=1, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='indiantime', full_name='ReceiveAsset.indiantime', index=2,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='idx', full_name='ReceiveAsset.idx', index=3,
      number=3, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='at_which_asset_expires', full_name='ReceiveAsset.at_which_asset_expires', index=4,
      number=5, type=2, cpp_type=6, label=1,
      has_default_value=False, default_value=float(0),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='org_name', full_name='ReceiveAsset.org_name', index=5,
      number=6, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='org_address', full_name='ReceiveAsset.org_address', index=6,
      number=7, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='org_role', full_name='ReceiveAsset.org_role', index=7,
      number=8, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='receive_asset_details', full_name='ReceiveAsset.receive_asset_details', index=8,
      number=9, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='child_zero_pub', full_name='ReceiveAsset.child_zero_pub', index=9,
      number=10, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='signed_nonce', full_name='ReceiveAsset.signed_nonce', index=10,
      number=11, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='nonce', full_name='ReceiveAsset.nonce', index=11,
      number=12, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='nonce_hash', full_name='ReceiveAsset.nonce_hash', index=12,
      number=13, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='public', full_name='ReceiveAsset.public', index=13,
      number=15, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='unique_code_hash', full_name='ReceiveAsset.unique_code_hash', index=14,
      number=16, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='encrypted_unique_code', full_name='ReceiveAsset.encrypted_unique_code', index=15,
      number=17, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='encrypted_admin_unique_code', full_name='ReceiveAsset.encrypted_admin_unique_code', index=16,
      number=18, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
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
  serialized_start=24,
  serialized_end=433,
)


_CRECEIVEASSETDETAILS = _descriptor.Descriptor(
  name='CReceiveAssetDetails',
  full_name='CReceiveAssetDetails',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='name', full_name='CReceiveAssetDetails.name', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='description', full_name='CReceiveAssetDetails.description', index=1,
      number=5, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
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
  serialized_start=435,
  serialized_end=492,
)

_RECEIVEASSET.fields_by_name['receive_asset_details'].message_type = _CRECEIVEASSETDETAILS
DESCRIPTOR.message_types_by_name['ReceiveAsset'] = _RECEIVEASSET
DESCRIPTOR.message_types_by_name['CReceiveAssetDetails'] = _CRECEIVEASSETDETAILS
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

ReceiveAsset = _reflection.GeneratedProtocolMessageType('ReceiveAsset', (_message.Message,), dict(
  DESCRIPTOR = _RECEIVEASSET,
  __module__ = 'receive_asset_pb2'
  # @@protoc_insertion_point(class_scope:ReceiveAsset)
  ))
_sym_db.RegisterMessage(ReceiveAsset)

CReceiveAssetDetails = _reflection.GeneratedProtocolMessageType('CReceiveAssetDetails', (_message.Message,), dict(
  DESCRIPTOR = _CRECEIVEASSETDETAILS,
  __module__ = 'receive_asset_pb2'
  # @@protoc_insertion_point(class_scope:CReceiveAssetDetails)
  ))
_sym_db.RegisterMessage(CReceiveAssetDetails)


# @@protoc_insertion_point(module_scope)
