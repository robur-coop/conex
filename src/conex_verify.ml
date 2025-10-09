open Conex_utils
open Conex_resource

type error = [
  | `UnknownKey of identifier
  | `InvalidBase64Encoding of identifier
  | `InvalidSignature of identifier
  | `InvalidPublicKey of identifier
  | `BadAlgorithm of string
]

let pp_error ppf = function
  | `UnknownKey id -> Format.fprintf ppf "unknown public key %a" pp_id id
  | `InvalidBase64Encoding id -> Format.fprintf ppf "signature %a: no valid base64 encoding" pp_id id
  | `InvalidSignature id -> Format.fprintf ppf "invalid signature %a" pp_id id
  | `InvalidPublicKey id -> Format.fprintf ppf "invalid public key %a" pp_id id
  | `BadAlgorithm msg -> Format.fprintf ppf "bad algorithm %s" msg
[@@coverage off]

module type S_BACK = sig
  val verify_rsa_pss : key:string -> data:string -> signature:string -> identifier -> (unit, [> error ]) result

  val verify_ed25519 : key:string -> data:string -> signature:string -> identifier -> (unit, [> error ]) result

  val sha256 : string -> string
end

module type S = sig
  val raw_digest : string -> Digest.t

  val digest : Wire.t -> Digest.t

  val verify : Wire.t -> Key.t M.t -> Signature.t M.t ->
    identifier Digest_map.t * error list
end

(** Instantiation. *)
module Make (C : S_BACK) = struct

  let raw_digest data = `SHA256, C.sha256 data

  let digest data = raw_digest (Wire.to_string data)

  let verify_signature data key (id, created, alg, signature) =
    match alg, key with
    | `RSA_PSS_SHA256, (_, _, `RSA, key) ->
      let data = Wire.to_string (to_be_signed data created id alg) in
      C.verify_rsa_pss ~key ~data ~signature id
    | `Ed25519, (_, _, `Ed25519, key) ->
      let data = Wire.to_string (to_be_signed data created id alg) in
      C.verify_ed25519 ~key ~data ~signature id
    | _ ->
      Error (`BadAlgorithm "only RSA (RSA_PSS) and ED25519 are supported")

  (* using a digest map here to uniquify the public keys! *)
  let verify data keys sigs =
    M.fold (fun _ (id, created, alg, s) (ok, err) ->
        match M.find_opt id keys with
        | None -> (ok, `UnknownKey id :: err)
        | Some key ->
          match verify_signature data key (id, created, alg, s) with
          | Ok () ->
            let dgst = Key.keyid raw_digest key in
            (Digest_map.add dgst id ok, err)
          | Error e -> (ok, e :: err))
      sigs (Digest_map.empty, [])
end
