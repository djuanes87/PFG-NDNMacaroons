// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: e_macaroon.proto

#ifndef PROTOBUF_e_5fmacaroon_2eproto__INCLUDED
#define PROTOBUF_e_5fmacaroon_2eproto__INCLUDED

#include <string>

#include <google/protobuf/stubs/common.h>

#if GOOGLE_PROTOBUF_VERSION < 3000000
#error This file was generated by a newer version of protoc which is
#error incompatible with your Protocol Buffer headers.  Please update
#error your headers.
#endif
#if 3000000 < GOOGLE_PROTOBUF_MIN_PROTOC_VERSION
#error This file was generated by an older version of protoc which is
#error incompatible with your Protocol Buffer headers.  Please
#error regenerate this file with a newer version of protoc.
#endif

#include <google/protobuf/arena.h>
#include <google/protobuf/arenastring.h>
#include <google/protobuf/generated_message_util.h>
#include <google/protobuf/metadata.h>
#include <google/protobuf/message.h>
#include <google/protobuf/repeated_field.h>
#include <google/protobuf/extension_set.h>
#include <google/protobuf/unknown_field_set.h>
// @@protoc_insertion_point(includes)

namespace macaroons {

// Internal implementation detail -- do not call these.
void protobuf_AddDesc_e_5fmacaroon_2eproto();
void protobuf_AssignDesc_e_5fmacaroon_2eproto();
void protobuf_ShutdownFile_e_5fmacaroon_2eproto();

class e_macaroon;
class e_macaroon_Endorsement;

// ===================================================================

class e_macaroon_Endorsement : public ::google::protobuf::Message /* @@protoc_insertion_point(class_definition:macaroons.e_macaroon.Endorsement) */ {
 public:
  e_macaroon_Endorsement();
  virtual ~e_macaroon_Endorsement();

  e_macaroon_Endorsement(const e_macaroon_Endorsement& from);

  inline e_macaroon_Endorsement& operator=(const e_macaroon_Endorsement& from) {
    CopyFrom(from);
    return *this;
  }

  inline const ::google::protobuf::UnknownFieldSet& unknown_fields() const {
    return _internal_metadata_.unknown_fields();
  }

  inline ::google::protobuf::UnknownFieldSet* mutable_unknown_fields() {
    return _internal_metadata_.mutable_unknown_fields();
  }

  static const ::google::protobuf::Descriptor* descriptor();
  static const e_macaroon_Endorsement& default_instance();

  void Swap(e_macaroon_Endorsement* other);

  // implements Message ----------------------------------------------

  inline e_macaroon_Endorsement* New() const { return New(NULL); }

  e_macaroon_Endorsement* New(::google::protobuf::Arena* arena) const;
  void CopyFrom(const ::google::protobuf::Message& from);
  void MergeFrom(const ::google::protobuf::Message& from);
  void CopyFrom(const e_macaroon_Endorsement& from);
  void MergeFrom(const e_macaroon_Endorsement& from);
  void Clear();
  bool IsInitialized() const;

  int ByteSize() const;
  bool MergePartialFromCodedStream(
      ::google::protobuf::io::CodedInputStream* input);
  void SerializeWithCachedSizes(
      ::google::protobuf::io::CodedOutputStream* output) const;
  ::google::protobuf::uint8* InternalSerializeWithCachedSizesToArray(
      bool deterministic, ::google::protobuf::uint8* output) const;
  ::google::protobuf::uint8* SerializeWithCachedSizesToArray(::google::protobuf::uint8* output) const {
    return InternalSerializeWithCachedSizesToArray(false, output);
  }
  int GetCachedSize() const { return _cached_size_; }
  private:
  void SharedCtor();
  void SharedDtor();
  void SetCachedSize(int size) const;
  void InternalSwap(e_macaroon_Endorsement* other);
  private:
  inline ::google::protobuf::Arena* GetArenaNoVirtual() const {
    return _internal_metadata_.arena();
  }
  inline void* MaybeArenaPtr() const {
    return _internal_metadata_.raw_arena_ptr();
  }
  public:

  ::google::protobuf::Metadata GetMetadata() const;

  // nested types ----------------------------------------------------

  // accessors -------------------------------------------------------

  // required string kind = 1;
  bool has_kind() const;
  void clear_kind();
  static const int kKindFieldNumber = 1;
  const ::std::string& kind() const;
  void set_kind(const ::std::string& value);
  void set_kind(const char* value);
  void set_kind(const char* value, size_t size);
  ::std::string* mutable_kind();
  ::std::string* release_kind();
  void set_allocated_kind(::std::string* kind);

  // required string name = 2;
  bool has_name() const;
  void clear_name();
  static const int kNameFieldNumber = 2;
  const ::std::string& name() const;
  void set_name(const ::std::string& value);
  void set_name(const char* value);
  void set_name(const char* value, size_t size);
  ::std::string* mutable_name();
  ::std::string* release_name();
  void set_allocated_name(::std::string* name);

  // required string certname = 3;
  bool has_certname() const;
  void clear_certname();
  static const int kCertnameFieldNumber = 3;
  const ::std::string& certname() const;
  void set_certname(const ::std::string& value);
  void set_certname(const char* value);
  void set_certname(const char* value, size_t size);
  ::std::string* mutable_certname();
  ::std::string* release_certname();
  void set_allocated_certname(::std::string* certname);

  // @@protoc_insertion_point(class_scope:macaroons.e_macaroon.Endorsement)
 private:
  inline void set_has_kind();
  inline void clear_has_kind();
  inline void set_has_name();
  inline void clear_has_name();
  inline void set_has_certname();
  inline void clear_has_certname();

  // helper for ByteSize()
  int RequiredFieldsByteSizeFallback() const;

  ::google::protobuf::internal::InternalMetadataWithArena _internal_metadata_;
  ::google::protobuf::uint32 _has_bits_[1];
  mutable int _cached_size_;
  ::google::protobuf::internal::ArenaStringPtr kind_;
  ::google::protobuf::internal::ArenaStringPtr name_;
  ::google::protobuf::internal::ArenaStringPtr certname_;
  friend void  protobuf_AddDesc_e_5fmacaroon_2eproto();
  friend void protobuf_AssignDesc_e_5fmacaroon_2eproto();
  friend void protobuf_ShutdownFile_e_5fmacaroon_2eproto();

  void InitAsDefaultInstance();
  static e_macaroon_Endorsement* default_instance_;
};
// -------------------------------------------------------------------

class e_macaroon : public ::google::protobuf::Message /* @@protoc_insertion_point(class_definition:macaroons.e_macaroon) */ {
 public:
  e_macaroon();
  virtual ~e_macaroon();

  e_macaroon(const e_macaroon& from);

  inline e_macaroon& operator=(const e_macaroon& from) {
    CopyFrom(from);
    return *this;
  }

  inline const ::google::protobuf::UnknownFieldSet& unknown_fields() const {
    return _internal_metadata_.unknown_fields();
  }

  inline ::google::protobuf::UnknownFieldSet* mutable_unknown_fields() {
    return _internal_metadata_.mutable_unknown_fields();
  }

  static const ::google::protobuf::Descriptor* descriptor();
  static const e_macaroon& default_instance();

  void Swap(e_macaroon* other);

  // implements Message ----------------------------------------------

  inline e_macaroon* New() const { return New(NULL); }

  e_macaroon* New(::google::protobuf::Arena* arena) const;
  void CopyFrom(const ::google::protobuf::Message& from);
  void MergeFrom(const ::google::protobuf::Message& from);
  void CopyFrom(const e_macaroon& from);
  void MergeFrom(const e_macaroon& from);
  void Clear();
  bool IsInitialized() const;

  int ByteSize() const;
  bool MergePartialFromCodedStream(
      ::google::protobuf::io::CodedInputStream* input);
  void SerializeWithCachedSizes(
      ::google::protobuf::io::CodedOutputStream* output) const;
  ::google::protobuf::uint8* InternalSerializeWithCachedSizesToArray(
      bool deterministic, ::google::protobuf::uint8* output) const;
  ::google::protobuf::uint8* SerializeWithCachedSizesToArray(::google::protobuf::uint8* output) const {
    return InternalSerializeWithCachedSizesToArray(false, output);
  }
  int GetCachedSize() const { return _cached_size_; }
  private:
  void SharedCtor();
  void SharedDtor();
  void SetCachedSize(int size) const;
  void InternalSwap(e_macaroon* other);
  private:
  inline ::google::protobuf::Arena* GetArenaNoVirtual() const {
    return _internal_metadata_.arena();
  }
  inline void* MaybeArenaPtr() const {
    return _internal_metadata_.raw_arena_ptr();
  }
  public:

  ::google::protobuf::Metadata GetMetadata() const;

  // nested types ----------------------------------------------------

  typedef e_macaroon_Endorsement Endorsement;

  // accessors -------------------------------------------------------

  // required string macaroon = 1;
  bool has_macaroon() const;
  void clear_macaroon();
  static const int kMacaroonFieldNumber = 1;
  const ::std::string& macaroon() const;
  void set_macaroon(const ::std::string& value);
  void set_macaroon(const char* value);
  void set_macaroon(const char* value, size_t size);
  ::std::string* mutable_macaroon();
  ::std::string* release_macaroon();
  void set_allocated_macaroon(::std::string* macaroon);

  // repeated .macaroons.e_macaroon.Endorsement endorsements = 2;
  int endorsements_size() const;
  void clear_endorsements();
  static const int kEndorsementsFieldNumber = 2;
  const ::macaroons::e_macaroon_Endorsement& endorsements(int index) const;
  ::macaroons::e_macaroon_Endorsement* mutable_endorsements(int index);
  ::macaroons::e_macaroon_Endorsement* add_endorsements();
  ::google::protobuf::RepeatedPtrField< ::macaroons::e_macaroon_Endorsement >*
      mutable_endorsements();
  const ::google::protobuf::RepeatedPtrField< ::macaroons::e_macaroon_Endorsement >&
      endorsements() const;

  // @@protoc_insertion_point(class_scope:macaroons.e_macaroon)
 private:
  inline void set_has_macaroon();
  inline void clear_has_macaroon();

  ::google::protobuf::internal::InternalMetadataWithArena _internal_metadata_;
  ::google::protobuf::uint32 _has_bits_[1];
  mutable int _cached_size_;
  ::google::protobuf::internal::ArenaStringPtr macaroon_;
  ::google::protobuf::RepeatedPtrField< ::macaroons::e_macaroon_Endorsement > endorsements_;
  friend void  protobuf_AddDesc_e_5fmacaroon_2eproto();
  friend void protobuf_AssignDesc_e_5fmacaroon_2eproto();
  friend void protobuf_ShutdownFile_e_5fmacaroon_2eproto();

  void InitAsDefaultInstance();
  static e_macaroon* default_instance_;
};
// ===================================================================


// ===================================================================

#if !PROTOBUF_INLINE_NOT_IN_HEADERS
// e_macaroon_Endorsement

// required string kind = 1;
inline bool e_macaroon_Endorsement::has_kind() const {
  return (_has_bits_[0] & 0x00000001u) != 0;
}
inline void e_macaroon_Endorsement::set_has_kind() {
  _has_bits_[0] |= 0x00000001u;
}
inline void e_macaroon_Endorsement::clear_has_kind() {
  _has_bits_[0] &= ~0x00000001u;
}
inline void e_macaroon_Endorsement::clear_kind() {
  kind_.ClearToEmptyNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
  clear_has_kind();
}
inline const ::std::string& e_macaroon_Endorsement::kind() const {
  // @@protoc_insertion_point(field_get:macaroons.e_macaroon.Endorsement.kind)
  return kind_.GetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline void e_macaroon_Endorsement::set_kind(const ::std::string& value) {
  set_has_kind();
  kind_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), value);
  // @@protoc_insertion_point(field_set:macaroons.e_macaroon.Endorsement.kind)
}
inline void e_macaroon_Endorsement::set_kind(const char* value) {
  set_has_kind();
  kind_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), ::std::string(value));
  // @@protoc_insertion_point(field_set_char:macaroons.e_macaroon.Endorsement.kind)
}
inline void e_macaroon_Endorsement::set_kind(const char* value, size_t size) {
  set_has_kind();
  kind_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(),
      ::std::string(reinterpret_cast<const char*>(value), size));
  // @@protoc_insertion_point(field_set_pointer:macaroons.e_macaroon.Endorsement.kind)
}
inline ::std::string* e_macaroon_Endorsement::mutable_kind() {
  set_has_kind();
  // @@protoc_insertion_point(field_mutable:macaroons.e_macaroon.Endorsement.kind)
  return kind_.MutableNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline ::std::string* e_macaroon_Endorsement::release_kind() {
  // @@protoc_insertion_point(field_release:macaroons.e_macaroon.Endorsement.kind)
  clear_has_kind();
  return kind_.ReleaseNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline void e_macaroon_Endorsement::set_allocated_kind(::std::string* kind) {
  if (kind != NULL) {
    set_has_kind();
  } else {
    clear_has_kind();
  }
  kind_.SetAllocatedNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), kind);
  // @@protoc_insertion_point(field_set_allocated:macaroons.e_macaroon.Endorsement.kind)
}

// required string name = 2;
inline bool e_macaroon_Endorsement::has_name() const {
  return (_has_bits_[0] & 0x00000002u) != 0;
}
inline void e_macaroon_Endorsement::set_has_name() {
  _has_bits_[0] |= 0x00000002u;
}
inline void e_macaroon_Endorsement::clear_has_name() {
  _has_bits_[0] &= ~0x00000002u;
}
inline void e_macaroon_Endorsement::clear_name() {
  name_.ClearToEmptyNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
  clear_has_name();
}
inline const ::std::string& e_macaroon_Endorsement::name() const {
  // @@protoc_insertion_point(field_get:macaroons.e_macaroon.Endorsement.name)
  return name_.GetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline void e_macaroon_Endorsement::set_name(const ::std::string& value) {
  set_has_name();
  name_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), value);
  // @@protoc_insertion_point(field_set:macaroons.e_macaroon.Endorsement.name)
}
inline void e_macaroon_Endorsement::set_name(const char* value) {
  set_has_name();
  name_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), ::std::string(value));
  // @@protoc_insertion_point(field_set_char:macaroons.e_macaroon.Endorsement.name)
}
inline void e_macaroon_Endorsement::set_name(const char* value, size_t size) {
  set_has_name();
  name_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(),
      ::std::string(reinterpret_cast<const char*>(value), size));
  // @@protoc_insertion_point(field_set_pointer:macaroons.e_macaroon.Endorsement.name)
}
inline ::std::string* e_macaroon_Endorsement::mutable_name() {
  set_has_name();
  // @@protoc_insertion_point(field_mutable:macaroons.e_macaroon.Endorsement.name)
  return name_.MutableNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline ::std::string* e_macaroon_Endorsement::release_name() {
  // @@protoc_insertion_point(field_release:macaroons.e_macaroon.Endorsement.name)
  clear_has_name();
  return name_.ReleaseNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline void e_macaroon_Endorsement::set_allocated_name(::std::string* name) {
  if (name != NULL) {
    set_has_name();
  } else {
    clear_has_name();
  }
  name_.SetAllocatedNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), name);
  // @@protoc_insertion_point(field_set_allocated:macaroons.e_macaroon.Endorsement.name)
}

// required string certname = 3;
inline bool e_macaroon_Endorsement::has_certname() const {
  return (_has_bits_[0] & 0x00000004u) != 0;
}
inline void e_macaroon_Endorsement::set_has_certname() {
  _has_bits_[0] |= 0x00000004u;
}
inline void e_macaroon_Endorsement::clear_has_certname() {
  _has_bits_[0] &= ~0x00000004u;
}
inline void e_macaroon_Endorsement::clear_certname() {
  certname_.ClearToEmptyNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
  clear_has_certname();
}
inline const ::std::string& e_macaroon_Endorsement::certname() const {
  // @@protoc_insertion_point(field_get:macaroons.e_macaroon.Endorsement.certname)
  return certname_.GetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline void e_macaroon_Endorsement::set_certname(const ::std::string& value) {
  set_has_certname();
  certname_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), value);
  // @@protoc_insertion_point(field_set:macaroons.e_macaroon.Endorsement.certname)
}
inline void e_macaroon_Endorsement::set_certname(const char* value) {
  set_has_certname();
  certname_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), ::std::string(value));
  // @@protoc_insertion_point(field_set_char:macaroons.e_macaroon.Endorsement.certname)
}
inline void e_macaroon_Endorsement::set_certname(const char* value, size_t size) {
  set_has_certname();
  certname_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(),
      ::std::string(reinterpret_cast<const char*>(value), size));
  // @@protoc_insertion_point(field_set_pointer:macaroons.e_macaroon.Endorsement.certname)
}
inline ::std::string* e_macaroon_Endorsement::mutable_certname() {
  set_has_certname();
  // @@protoc_insertion_point(field_mutable:macaroons.e_macaroon.Endorsement.certname)
  return certname_.MutableNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline ::std::string* e_macaroon_Endorsement::release_certname() {
  // @@protoc_insertion_point(field_release:macaroons.e_macaroon.Endorsement.certname)
  clear_has_certname();
  return certname_.ReleaseNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline void e_macaroon_Endorsement::set_allocated_certname(::std::string* certname) {
  if (certname != NULL) {
    set_has_certname();
  } else {
    clear_has_certname();
  }
  certname_.SetAllocatedNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), certname);
  // @@protoc_insertion_point(field_set_allocated:macaroons.e_macaroon.Endorsement.certname)
}

// -------------------------------------------------------------------

// e_macaroon

// required string macaroon = 1;
inline bool e_macaroon::has_macaroon() const {
  return (_has_bits_[0] & 0x00000001u) != 0;
}
inline void e_macaroon::set_has_macaroon() {
  _has_bits_[0] |= 0x00000001u;
}
inline void e_macaroon::clear_has_macaroon() {
  _has_bits_[0] &= ~0x00000001u;
}
inline void e_macaroon::clear_macaroon() {
  macaroon_.ClearToEmptyNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
  clear_has_macaroon();
}
inline const ::std::string& e_macaroon::macaroon() const {
  // @@protoc_insertion_point(field_get:macaroons.e_macaroon.macaroon)
  return macaroon_.GetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline void e_macaroon::set_macaroon(const ::std::string& value) {
  set_has_macaroon();
  macaroon_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), value);
  // @@protoc_insertion_point(field_set:macaroons.e_macaroon.macaroon)
}
inline void e_macaroon::set_macaroon(const char* value) {
  set_has_macaroon();
  macaroon_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), ::std::string(value));
  // @@protoc_insertion_point(field_set_char:macaroons.e_macaroon.macaroon)
}
inline void e_macaroon::set_macaroon(const char* value, size_t size) {
  set_has_macaroon();
  macaroon_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(),
      ::std::string(reinterpret_cast<const char*>(value), size));
  // @@protoc_insertion_point(field_set_pointer:macaroons.e_macaroon.macaroon)
}
inline ::std::string* e_macaroon::mutable_macaroon() {
  set_has_macaroon();
  // @@protoc_insertion_point(field_mutable:macaroons.e_macaroon.macaroon)
  return macaroon_.MutableNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline ::std::string* e_macaroon::release_macaroon() {
  // @@protoc_insertion_point(field_release:macaroons.e_macaroon.macaroon)
  clear_has_macaroon();
  return macaroon_.ReleaseNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline void e_macaroon::set_allocated_macaroon(::std::string* macaroon) {
  if (macaroon != NULL) {
    set_has_macaroon();
  } else {
    clear_has_macaroon();
  }
  macaroon_.SetAllocatedNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), macaroon);
  // @@protoc_insertion_point(field_set_allocated:macaroons.e_macaroon.macaroon)
}

// repeated .macaroons.e_macaroon.Endorsement endorsements = 2;
inline int e_macaroon::endorsements_size() const {
  return endorsements_.size();
}
inline void e_macaroon::clear_endorsements() {
  endorsements_.Clear();
}
inline const ::macaroons::e_macaroon_Endorsement& e_macaroon::endorsements(int index) const {
  // @@protoc_insertion_point(field_get:macaroons.e_macaroon.endorsements)
  return endorsements_.Get(index);
}
inline ::macaroons::e_macaroon_Endorsement* e_macaroon::mutable_endorsements(int index) {
  // @@protoc_insertion_point(field_mutable:macaroons.e_macaroon.endorsements)
  return endorsements_.Mutable(index);
}
inline ::macaroons::e_macaroon_Endorsement* e_macaroon::add_endorsements() {
  // @@protoc_insertion_point(field_add:macaroons.e_macaroon.endorsements)
  return endorsements_.Add();
}
inline ::google::protobuf::RepeatedPtrField< ::macaroons::e_macaroon_Endorsement >*
e_macaroon::mutable_endorsements() {
  // @@protoc_insertion_point(field_mutable_list:macaroons.e_macaroon.endorsements)
  return &endorsements_;
}
inline const ::google::protobuf::RepeatedPtrField< ::macaroons::e_macaroon_Endorsement >&
e_macaroon::endorsements() const {
  // @@protoc_insertion_point(field_list:macaroons.e_macaroon.endorsements)
  return endorsements_;
}

#endif  // !PROTOBUF_INLINE_NOT_IN_HEADERS
// -------------------------------------------------------------------


// @@protoc_insertion_point(namespace_scope)

}  // namespace macaroons

// @@protoc_insertion_point(global_scope)

#endif  // PROTOBUF_e_5fmacaroon_2eproto__INCLUDED
