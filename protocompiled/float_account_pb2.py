# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: float_account.proto

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
  name='float_account.proto',
  package='',
  syntax='proto3',
  serialized_pb=_b('\n\x13\x66loat_account.proto\"\xaa\x03\n\x0c\x46loatAccount\x12\x10\n\x08org_name\x18\x01 \x01(\t\x12\x0f\n\x07pancard\x18\x02 \x01(\t\x12\x14\n\x0cphone_number\x18\x03 \x01(\t\x12\r\n\x05\x65mail\x18\x04 \x01(\t\x12\x12\n\ngst_number\x18\x05 \x01(\t\x12\x12\n\ntan_number\x18\x06 \x01(\t\x12\x0f\n\x07\x63laimed\x18\x07 \x01(\x08\x12\x12\n\nclaimed_by\x18\x08 \x01(\t\x12\x1d\n\x11\x63reate_asset_idxs\x18\t \x03(\rB\x02\x10\x01\x12\x12\n\nparent_idx\x18\n \x01(\r\x12\x0c\n\x04time\x18\x0b \x01(\r\x12\x13\n\x0bindian_time\x18\x0c \x01(\t\x12\x12\n\nclaimed_on\x18\r \x01(\t\x12\x13\n\x0bparent_role\x18\x0e \x01(\t\x12\x0c\n\x04role\x18\x0f \x01(\t\x12\x17\n\x0fparent_zero_pub\x18\x10 \x01(\t\x12\x16\n\x0e\x63hild_zero_pub\x18\x14 \x01(\t\x12\x14\n\x0csigned_nonce\x18\x11 \x01(\t\x12\r\n\x05nonce\x18\x12 \x01(\r\x12\x12\n\nnonce_hash\x18\x13 \x01(\t\x12\x0e\n\x06public\x18\x15 \x01(\tb\x06proto3')
)




_FLOATACCOUNT = _descriptor.Descriptor(
  name='FloatAccount',
  full_name='FloatAccount',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='org_name', full_name='FloatAccount.org_name', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='pancard', full_name='FloatAccount.pancard', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='phone_number', full_name='FloatAccount.phone_number', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='email', full_name='FloatAccount.email', index=3,
      number=4, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='gst_number', full_name='FloatAccount.gst_number', index=4,
      number=5, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='tan_number', full_name='FloatAccount.tan_number', index=5,
      number=6, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='claimed', full_name='FloatAccount.claimed', index=6,
      number=7, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='claimed_by', full_name='FloatAccount.claimed_by', index=7,
      number=8, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='create_asset_idxs', full_name='FloatAccount.create_asset_idxs', index=8,
      number=9, type=13, cpp_type=3, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=_descriptor._ParseOptions(descriptor_pb2.FieldOptions(), _b('\020\001')), file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='parent_idx', full_name='FloatAccount.parent_idx', index=9,
      number=10, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='time', full_name='FloatAccount.time', index=10,
      number=11, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='indian_time', full_name='FloatAccount.indian_time', index=11,
      number=12, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='claimed_on', full_name='FloatAccount.claimed_on', index=12,
      number=13, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='parent_role', full_name='FloatAccount.parent_role', index=13,
      number=14, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='role', full_name='FloatAccount.role', index=14,
      number=15, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='parent_zero_pub', full_name='FloatAccount.parent_zero_pub', index=15,
      number=16, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='child_zero_pub', full_name='FloatAccount.child_zero_pub', index=16,
      number=20, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='signed_nonce', full_name='FloatAccount.signed_nonce', index=17,
      number=17, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='nonce', full_name='FloatAccount.nonce', index=18,
      number=18, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='nonce_hash', full_name='FloatAccount.nonce_hash', index=19,
      number=19, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='public', full_name='FloatAccount.public', index=20,
      number=21, type=9, cpp_type=9, label=1,
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
  serialized_end=450,
)

DESCRIPTOR.message_types_by_name['FloatAccount'] = _FLOATACCOUNT
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

FloatAccount = _reflection.GeneratedProtocolMessageType('FloatAccount', (_message.Message,), dict(
  DESCRIPTOR = _FLOATACCOUNT,
  __module__ = 'float_account_pb2'
  # @@protoc_insertion_point(class_scope:FloatAccount)
  ))
_sym_db.RegisterMessage(FloatAccount)


_FLOATACCOUNT.fields_by_name['create_asset_idxs'].has_options = True
_FLOATACCOUNT.fields_by_name['create_asset_idxs']._options = _descriptor._ParseOptions(descriptor_pb2.FieldOptions(), _b('\020\001'))
# @@protoc_insertion_point(module_scope)
