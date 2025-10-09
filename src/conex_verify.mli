(** Verification primitives

    Implementations are provided in {!Conex_mirage_crypto} and {!Conex_openssl}. *)

open Conex_utils
open Conex_resource

(** Potential error case when verifying a signature *)
type error = [
  | `UnknownKey of identifier
  | `InvalidBase64Encoding of identifier
  | `InvalidSignature of identifier
  | `InvalidPublicKey of identifier
  | `BadAlgorithm of string
]

(** [pp_error] is a pretty printer for [verification_error]. *)
val pp_error : error fmt

(** The verification module type *)
module type S = sig

  (** [raw_digest str] is the digest of the given [str]. *)
  val raw_digest : string -> Digest.t

  (** [digest wire] is the digest of the {{!Conex_resource.Wire.to_string}string
      encoding} of [wire]. *)
  val digest : Wire.t -> Digest.t

  (** [verify wire keys sigs] is the set of valid signatures and errors *)
  val verify : Wire.t -> Key.t M.t -> Signature.t M.t ->
    identifier Digest_map.t * error list
end

(** The verification backend, to be implemented by a crypto provider *)
module type S_BACK = sig

  (** [verify_rsa_pss ~key ~data ~signature] returns [Ok ()] on success,
      otherwise a [verification_error].  Currently, SHA256 is used as hash
      algorithm. *)
  val verify_rsa_pss : key:string -> data:string -> signature:string -> identifier ->
    (unit, [> error ]) result

  (** [verify_ed25519 ~key ~data ~signature] returns [Ok ()] on success,
      otherwise a [verification_error]. *)
  val verify_ed25519 : key:string -> data:string -> signature:string -> identifier ->
    (unit, [> error ]) result

  (** [sha256 str] computes the SHA256 digest of [str] and converts it to
      hex. *)
  val sha256 : string -> string
end

(** Instantiation. *)
module Make (C : S_BACK) : S
