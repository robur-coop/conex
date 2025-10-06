open Conex_utils

module V = struct
  let good_rsa p = Mirage_crypto_pk.Rsa.pub_bits p >= 2048

  let encode_key pub =
    String.trim (X509.Public_key.encode_pem (`RSA pub))

  let decode_key data =
    Result.fold
      ~error:(fun _ -> None)
      ~ok:(function `RSA pub -> Some pub | _ -> None)
      (X509.Public_key.decode_pem data)

  module Pss_sha256 = Mirage_crypto_pk.Rsa.PSS (Digestif.SHA256)

  let verify_rsa_pss ~key ~data ~signature id =
    let ( let* ) = Result.bind in
    let* signature =
      Result.map_error (fun _ -> `InvalidBase64Encoding id)
        (Base64.decode signature)
    in
    let* key =
      Option.to_result ~none:(`InvalidPublicKey id) (decode_key key)
    in
    let* () = guard (good_rsa key) (`InvalidPublicKey id) in
    guard (Pss_sha256.verify ~key ~signature (`Message data))
      (`InvalidSignature id)

  let verify_ed25519 ~key ~data ~signature id =
    let ( let* ) = Result.bind in
    let* signature =
      Result.map_error (fun _ -> `InvalidBase64Encoding id)
        (Base64.decode signature)
    in
    let* key =
      let* decoded =
        Result.map_error
          (fun (`Msg _msg) -> `InvalidPublicKey id (*(Fmt.str "id %s error %s" id msg)*))
          (Base64.decode key)
      in
      Result.map_error
        (fun _e ->
           `InvalidPublicKey id
           (*(Fmt.str "id %s error %a" id Mirage_crypto_ec.pp_error e) *))
        (Mirage_crypto_ec.Ed25519.pub_of_octets decoded)
    in
    guard (Mirage_crypto_ec.Ed25519.verify ~key signature ~msg:data)
      (`InvalidSignature id)

  let sha256 data =
    let check = Digestif.SHA256.(to_raw_string (digest_string data)) in
    Ohex.encode check
end

module NC_V = Conex_verify.Make (V)

module C = struct

  type t =
    Conex_resource.identifier * Conex_resource.timestamp *
    [ `Rsa of Mirage_crypto_pk.Rsa.priv | `Ed25519 of Mirage_crypto_ec.Ed25519.priv ]

  let created (_, ts, _) = ts

  let id (id, _, _) = id

  let alg (_, _, k) = match k with `Rsa _ -> `RSA | `Ed25519 _ -> `Ed25519

  let decode_priv id ts data =
    Result.fold
      ~ok:(function
          | `RSA priv -> Ok (id, ts, `Rsa priv)
          | `ED25519 priv -> Ok (id, ts, `Ed25519 priv)
          | _ -> Error "only RSA and Ed25519 keys supported")
      ~error:(function `Msg e -> Error e)
      (X509.Private_key.decode_pem data)

  let encode_priv p =
    let k = match p with
      | `Rsa r -> `RSA r
      | `Ed25519 k -> `ED25519 k
    in
    X509.Private_key.encode_pem k

  let pub_of_priv_raw = function
    | `Rsa k -> V.encode_key (Mirage_crypto_pk.Rsa.pub_of_priv k)
    | `Ed25519 k ->
      let pub = Mirage_crypto_ec.Ed25519.pub_of_priv k in
      Base64.encode_string (Mirage_crypto_ec.Ed25519.pub_to_octets pub)

  let generate ~alg ?(bits = 4096) () =
    let priv =
      match alg with
      | `RSA -> `Rsa (Mirage_crypto_pk.Rsa.generate ~bits ())
      | `Ed25519 -> `Ed25519 (fst (Mirage_crypto_ec.Ed25519.generate ()))
    in
    encode_priv priv, pub_of_priv_raw priv

  let bits (_, _, k) =
    match k with
    | `Rsa k -> Mirage_crypto_pk.Rsa.priv_bits k
    | `Ed25519 _ -> 255

  let pub_of_priv (_, _, k) = pub_of_priv_raw k

  let sign (_, _, key) data =
    let signature =
      match key with
      | `Rsa key -> V.Pss_sha256.sign ~key (`Message data)
      | `Ed25519 key -> Mirage_crypto_ec.Ed25519.sign ~key data
    in
    Ok (Base64.encode_string signature)

  let sha256 = V.sha256
end
