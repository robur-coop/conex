(** Persistent data: on wire and record types

    Every resource in conex is a piece of data (or metadata), and has its own
    purpose.  Resources stored on disk consists of a common header: a name, a
    type, a counter, an epoch, and a creation timestamp.  There are
    broadly three kinds of resources: those containing identities ({!Team} and
    {!Author}), those regulating access to packages ({!Authorisation}), and
    those with the digests of the opam repository data ({!Releases} and
    {!Release}).
*)

open Conex_utils

(* TODO: maybe move name, identifier, timestamp to conex_utils!? *)
(** {1 Names and identifiers} *)

(** The name of resources, used e.g. for package names. *)
type name = string

(** [pp_name name] is a pretty printer for [name]. *)
val pp_name : name fmt

(** [name_equal a b] is the result of a case insensitive comparison of [a] and [b]. *)
val name_equal : name -> name -> bool

(** The type of identifiers. *)
type identifier = string

(** [pp_id id] is a pretty printer for [identifier]. *)
val pp_id : identifier fmt

(** [id_equal a b] is the result of a case insensitive comparison of [a] and [b]. *)
val id_equal : identifier -> identifier -> bool

(** The type for a timestamp, always a RFC3339 string in UTC (no timezone
    information).  *)
type timestamp = string

(* TODO: should we have a constructor and check for validity?
   NNNN'-'MM'-'DD'T'hh':'mm':'ss'Z' where
   ^^ year, 1 <= MM <= 12, 1 <= DD <= 31 (or depending on MM)
   0 <= hh <= 23, 0 <= mm <= 59, 0 <= ss <= 59 *)

val pp_timestamp : timestamp fmt

(** {1 Wire format} *)

(** The wire encoding is abstract here, one suitable decoding and encoding
    engine is {!Conex_opam_encoding}.  The wire encoding is used for digest
    computations, and persistent storage on disk. *)
module Wire : sig

  (** The values in the key value store: either a map, a list, an identifier,
      data (represented as string), or an unsigned integer. *)
  type s =
    | Map of s M.t
    | List of s list
    | Identifier of identifier
    | Data of string
    | Bigint of Uint.t
    | Smallint of int
    | Pair of s * s
    | And of s * s
    | Or of s * s

  (** The toplevel node, a Map *)
  type t = s M.t

  (** [to_string t] is a string representing [t].  This is used by
      {!Conex_verify.S} to compute digests and signatures.  There is no parser for
      this string encoding available. *)
  val to_string : t -> string
end

(** {1 Resource types} *)

(** The sum type of all possible resources. *)
type typ = [
  | `Root
  | `Timestamp
  | `Snapshot
  | `Targets
]

(** [resource_to_string res] is the string representation of [res]. *)
val typ_to_string : typ -> string

(** [string_to_resource str] is either [Some resource] or [None]. *)
val string_to_typ : string -> typ option

(** [pp_resource pp] is a pretty printer for [resource]. *)
val pp_typ : typ fmt

(** [resource_equal a b] is [true] if they are the same, otherwise [false]. *)
val typ_equal : typ -> typ -> bool

val typ_of_wire : Wire.s -> (typ, string) result

type err = [
  | `Parse of string
  | `Unknown_alg of string
  | `Malformed
]

val pp_err : err fmt

(** Common header on disk *)
module Header : sig

  (** The header consists of version, created, counter, epoch, name, and typ. *)
  type t = {
    version : int ;
    created : timestamp ;
    counter : Uint.t ;
    epoch : Uint.t ;
    name : name ;
    typ : typ
  }

  (** [pp] is a pretty printer. *)
  val pp : t fmt

  (** [wire t] is the wire representation of [t]. *)
  val wire : t -> Wire.t

  (** [of_wire t] converts [t] into a {!Header.t} or error. *)
  val of_wire : Wire.t -> (t, string) result

  (** [counter ctr epoch] prints [ctr, epoch] to a string containing the counter
      and epoch (unless zero). *)
  val counter : Uint.t -> Uint.t -> string
end

(** {1 Digests} *)

module Digest : sig

  (** The sum type of supported digest algorithms. *)
  type alg = [ `SHA256 ]

  (** A digest is a pair of digest algorithm and value. *)
  type t = alg * string

  (** [pp digest] is a pretty printer for [digest]. *)
  val pp : t fmt

  (** [compare a b] compares [a] and [b], returns 0 if equal, -1 if smaller, 1
     if bigger. *)
  val compare : t -> t -> int

  (** [equal a b] is [true] when [a] and [b] use the same algorithm type, and
      have the same value. *)
  val equal : t -> t -> bool

  (** [of_wire w] converts [w] to a digest or error. *)
  val of_wire : Wire.s -> (t, err) result

  (** [wire_raw t] is the wire representation of [t]. *)
  val wire_raw : t -> Wire.s

  (** [of_string str] is t or an error. *)
  val of_string : string -> (t, err) result

  (** [to_string digest] is the [string] representing the [digest]. *)
  val to_string : t -> string
end

module Digest_map : sig
  include Map.S with type key = Digest.t
  val pp : (Format.formatter -> 'a -> unit) -> Format.formatter -> 'a t -> unit
end

(** {1 Asymmetric key types} *)

module Key : sig

  (** The sum type of supported asymmetric key algorithms. *)
  type alg = [ `RSA ]

  (** The type of public keys *)
  type t = identifier * timestamp * alg * string

  (** [equal a b] is [true] if id, created, alg, and key are identical. *)
  val equal : t -> t -> bool

  (** [pp] is a pretty printer for public keys *)
  val pp : t fmt

  (** [of_wire w] converts [w] to a key or error. *)
  val of_wire : Wire.s -> (t, err) result

  (** [many_of_wire w] uses {!of_wire} on the {!Wire.List} [w].  Prints errors
      to stdout if an unknown key algorithm or multiple keys with the same
      identifier are used. *)
  val many_of_wire : Wire.s list -> (t M.t * string list, string) result

  (** [wire_raw t] is the raw wire representation of [t]. *)
  val wire_raw : t -> Wire.s

  (** [wire t] is the wire representation of [t]. *)
  val wire : t -> Wire.t

  (** [keyid hash key] is [hash (to_string key)], the key hash. *)
  val keyid : (string -> Digest.t) -> t -> Digest.t

  val to_string : t -> string
end

(** {1 Cryptographic signatures} *)

module Signature : sig
  (** The sum type of supported signature algorithms. *)
  type alg = [ `RSA_PSS_SHA256 ]

  (** A signature is a quadruple of timestamp, identifier, algorithm, and
      signature value. *)
  type t = identifier * timestamp * alg * string

  (** [equal a b] is [true] if id, created, alg, and signature are the same. *)
  val equal : t -> t -> bool

  (** [pp sig] is a pretty printer for a signature. *)
  val pp : t fmt

  (** [of_wire w] converts [w] to a signature or error. *)
  val of_wire : Wire.s -> (t, err) result

  (** [many_of_wire w] uses {!of_wire} on the {!Wire.List} [w].  Prints errors to
     stdout if an unknown signature algorithm or multiple signatures with the
     same identifier are used. *)
  val many_of_wire : Wire.s list -> (t M.t * string list, string) result

  (** [wire_raw t] is the wire representation of [t]. *)
  val wire_raw : t -> Wire.s
end

(** [to_be_signed data timestamp id algorithm] prepares the representation used
   by signing and verification  *)
val to_be_signed : Wire.t -> timestamp -> identifier -> Signature.alg -> Wire.t


(** {1 Delegation key expression} *)
module Expression : sig

  type keyref =
    | Remote of identifier * Digest.t * Uint.t
    | Local of identifier

  module KS : (Set.S with type elt = keyref)

  type t =
    | Quorum of int * KS.t
    | And of t * t
    | Or of t * t

  val compare : t -> t -> int

  val equal : t -> t -> bool

  val local_keys : t -> S.t

  val keys : (Digest.t * Uint.t) M.t -> t -> (Digest.t * Uint.t) M.t

  val pp : t fmt

  val of_wire : Wire.s -> (t, string) result

  val to_wire : t -> Wire.s

  val hash : (string -> Digest.t) -> string M.t -> t -> (Digest.t, string) result

  val eval : t -> (identifier * Uint.t) Digest_map.t -> S.t -> bool
end

(** {1 Root} *)

(** The root contains the (offline) root keys, also defines snapshot, timestamp,
    and maintainers.  Furthermore, it contains configuration information such as
    where keys are located in this repository and where the data is stored. *)
module Root : sig
  type role = [ `Snapshot | `Timestamp | `Maintainer ]

  val role_to_string : role -> string

  module RM : sig
    include Map.S with type key = role
    val pp : (Format.formatter -> 'a -> unit) -> Format.formatter -> 'a t -> unit
  end

  type t = {
    created : timestamp ;
    counter : Uint.t ;
    epoch : Uint.t ;
    name : identifier ;
    datadir : path ;
    keydir : path ;
    keys : Key.t M.t ;
    valid : Expression.t ;
    roles : Expression.t RM.t ;
    signatures : Signature.t M.t ;
  }

  val t : ?counter:Uint.t -> ?epoch:Uint.t -> ?name:identifier ->
    ?datadir:path -> ?keydir:path -> ?keys:Key.t M.t -> ?roles:Expression.t RM.t ->
    ?signatures:Signature.t M.t -> timestamp -> Expression.t -> t

  val add_signature : t -> identifier -> Signature.t -> t

  val pp : t fmt

  val of_wire : Wire.t -> (t * string list, string) result

  val wire : t -> Wire.t

  val wire_raw : t -> Wire.t

end

(** {1 Target} *)

(** The target is a triple of filename, digest, and size. It is used by snapshot
    and targets. *)
module Target : sig
  type t = {
    filename : path ;
    digest : Digest.t list ;
    size : Uint.t ;
  }

  (** [equal a b] is [true] if targets [a] and [b] are identical. *)
  val equal : t -> t -> bool

  (** [valid_opam_path t] is [true] if the filename sticks to opam repository
      rules: [packages/foo/foo.version/opam], [packages/foo/foo.version/files/],
      [packages/foo.version/opam], or [packages/foo.version/files/]. *)
  val valid_opam_path : t -> bool

  (** [pp] is a pretty printer for a target. *)
  val pp : t fmt

  (** [of_wire w] converts [w] to a target or error. *)
  val of_wire : Wire.s -> (t, string) result

  (** [wire_raw t] is the raw wire representation of [t]. *)
  val wire_raw : t -> Wire.s
end

(** {1 Timestamp} *)

(** The timestamp is signed by the timestamp role. It lists the snapshot data,
    (its size, filename, and digest). The purpose is to prevent freeze attacks:
    It periodically signs the data, a client can discover it does not receive
    updates.
*)
module Timestamp : sig
  type t = {
    created : timestamp ;
    counter : Uint.t ;
    epoch : Uint.t ;
    name : identifier ;
    keys : Key.t M.t ;
    targets : Target.t list ;
    signatures : Signature.t M.t ;
  }

  val t : ?counter:Uint.t -> ?epoch:Uint.t -> ?keys:Key.t M.t ->
    ?targets:Target.t list -> ?signatures:Signature.t M.t -> timestamp ->
    identifier -> t

  (** [equal a b] is [true] if all fields of [a] and [b] are equal. *)
  val equal : t -> t -> bool

  val add_signature : t -> identifier -> Signature.t -> t

  val pp : t fmt

  val of_wire : Wire.t -> (t * string list, string) result

  val wire : t -> Wire.t

  val wire_raw : t -> Wire.t

end


(** {1 Snapshot} *)

(** The snapshot is signed by the snapshot role. It lists all targets, with
    size, filename, and digest. The purpose is to prevent mix-and-match attacks,
    where an attacker mixes older targets files with newer ones. *)
module Snapshot : sig
  type t = {
    created : timestamp ;
    counter : Uint.t ;
    epoch : Uint.t ;
    name : identifier ;
    keys : Key.t M.t ;
    targets : Target.t list ;
    signatures : Signature.t M.t ;
  }

  val t : ?counter:Uint.t -> ?epoch:Uint.t -> ?keys:Key.t M.t ->
    ?targets:Target.t list -> ?signatures:Signature.t M.t -> timestamp ->
    identifier -> t

  (** [equal a b] is [true] if all fields of [a] and [b] are equal. *)
  val equal : t -> t -> bool

  val add_signature : t -> identifier -> Signature.t -> t

  val pp : t fmt

  val of_wire : Wire.t -> (t * string list, string) result

  val wire : t -> Wire.t

  val wire_raw : t -> Wire.t

end

module Delegation : sig
  type t = {
    paths : path list ;
    valid : Expression.t ;
    terminating : bool
  }

  (** [equal a b] is [true] if delegations [a] and [b] are identical. *)
  val equal : t -> t -> bool

  (** [pp] is a pretty printer for a delegation. *)
  val pp : t fmt

  (** [of_wire w] converts [w] to a delegation or error. *)
  val of_wire : Wire.s -> (t, string) result

  (** [wire_raw t] is the raw wire representation of [t]. *)
  val wire_raw : t -> Wire.s
end

module Targets : sig
  type t = {
    created : timestamp ;
    counter : Uint.t ;
    epoch : Uint.t ;
    name : identifier ;
    keys : Key.t M.t ;
    valid : Expression.t ;
    delegations : Delegation.t list ;
    targets : Target.t list ;
    signatures : Signature.t M.t ;
  }

  val t : ?counter:Uint.t -> ?epoch:Uint.t -> ?keys:Key.t M.t ->
    ?delegations:Delegation.t list -> ?targets:Target.t list ->
    ?signatures:Signature.t M.t -> timestamp -> identifier -> Expression.t -> t

  val add_signature : t -> identifier -> Signature.t -> t

  (** [equal a b] is [true] if all fields of [a] and [b] are equal. *)
  val equal : t -> t -> bool

  (** [pp t] is a pretty printer for a targets. *)
  val pp : t fmt

  (** [of_wire w] converts [w] to a targets or error. *)
  val of_wire : Wire.t -> (t * string list, string) result

  (** [wire t] is the wire representation of [t]. *)
  val wire : t -> Wire.t

  (** [wire_raw t] is the wire representation of [t]. *)
  val wire_raw : t -> Wire.t
end
