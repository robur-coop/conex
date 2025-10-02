
(* why we have base64 here?  well, OpenSSL seems to not be able to do base64 correctly

command: echo -n 6w== | openssl base64 -d
output:
exit-code: 0

command: echo 6w== | openssl base64 -d | hexdump
output: 00eb
exit-code: 0

We could depend on base64/b64decode/..., but that's too much of a hassle.
Instead, we ship a B64 decoder. *)
module B64 = struct
  (* decoder from https://github.com/mirage/ocaml-base64,
     added checks when padding may occur to bail out early
  *)
(*
 * Copyright (c) 2006-2009 Citrix Systems Inc.
 * Copyright (c) 2010 Thomas Gazagnaire <thomas@gazagnaire.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *)

let default_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
let padding = '='

let of_char ?(alphabet=default_alphabet) may x =
  if may && x = padding then 0 else String.index alphabet x

let decode ?alphabet input =
  let length = String.length input in
  let input =
    if length mod 4 = 0 then input
    else input ^ (String.make (4 - length mod 4) padding)
  in
  let words = length / 4 in
  let padding =
    match length with
    | 0 -> 0
    | _ when input.[length - 2] = padding -> 2
    | _ when input.[length - 1] = padding -> 1
    | _ -> 0
  in
  let output = Bytes.make (words * 3 - padding) '\000' in
  let may_pad i idx = i = words - 1 && idx >= padding in
  for i = 0 to words - 1 do
    let a = of_char ?alphabet (may_pad i 0) (String.get input (4 * i + 0))
    and b = of_char ?alphabet (may_pad i 1) (String.get input (4 * i + 1))
    and c = of_char ?alphabet (may_pad i 2) (String.get input (4 * i + 2))
    and d = of_char ?alphabet (may_pad i 3) (String.get input (4 * i + 3)) in
    let n = (a lsl 18) lor (b lsl 12) lor (c lsl 6) lor d in
    let x = (n lsr 16) land 255
    and y = (n lsr 8) land 255
    and z = n land 255 in
    Bytes.set output (3 * i + 0) (char_of_int x);
    if i <> words - 1 || padding < 2 then
      Bytes.set output (3 * i + 1) (char_of_int y);
    if i <> words - 1 || padding < 1 then
      Bytes.set output (3 * i + 2) (char_of_int z);
  done;
  Bytes.unsafe_to_string output
end

open Conex_utils

let ( let* ) = Result.bind

module V = struct

  (* good OpenSSL versions:
     "OpenSSL 1.0.2g  1 Mar 2016" ; Ubuntu at cl.cam
     "OpenSSL 1.0.2j-freebsd  26 Sep 2016" ; FreeBSD 11 & -CURRENT
     "OpenSSL 1.0.1e 11 Feb 2013" ; debian 7.11
     "OpenSSL 1.0.1t" ; mindy
     "OpenSSL 1.0.2j-fips  26 Sep 2016" ; fedora qubes vm
     "OpenSSL 1.0.0u-dev" ; ln5
     "OpenSSL 1.0.1 14 Mar 2012" ; Travis CI
     "OpenSSL 1.0.0g" ; reynir

     bad ones (no PSS):
     "OpenSSL 0.9.8zh-freebsd 3 Dec 2015" ; FreeBSD 9.3
     "OpenSSL 0.9.8o 01 Jun 2010" ; debian 6.0.10
     "OpenSSL 0.9.8k" ; reynir
  *)

  let check_version () =
    let cmd = "openssl version" in
    let input = Unix.open_process_in cmd in
    let output = input_line input in
    let _ = Unix.close_process_in input in
    if String.is_prefix ~prefix:"OpenSSL 0." output then
      Error ("need at least OpenSSL 1.0.0(u?), found: " ^ output)
    else
      Ok ()

  let verify_rsa_pss ~key ~data ~signature id =
    let* signature =
      try Ok (B64.decode signature) with _ -> Error (`InvalidBase64Encoding id)
    in
    Result.map_error (function
        | "broken" -> `InvalidSignature id
        | _ -> `InvalidPublicKey id)
      (let filename = Filename.temp_file "conex" "sig" in
       let* () = Conex_unix_persistency.write_replace (filename ^ ".key") key in
       let* () = Conex_unix_persistency.write_replace (filename ^ ".txt") data in
       let* () = Conex_unix_persistency.write_replace (filename ^ ".sig") signature in
       let cmd = Printf.sprintf "openssl dgst -sha256 -verify %s.key -sigopt rsa_padding_mode:pss -signature %s.sig %s.txt > /dev/null" filename filename filename in
       let res = if 0 = Sys.command cmd then Ok () else Error "broken" in
       let _ = Conex_unix_persistency.remove (filename ^ ".txt")
       and _ = Conex_unix_persistency.remove (filename ^ ".key")
       and _ = Conex_unix_persistency.remove (filename ^ ".sig")
       and _ = Conex_unix_persistency.remove filename
       in
       res)

  let pem_of_ed25519 k =
    {|-----BEGIN PUBLIC KEY-----
nMCowBQYDK2VwAyEA|} ^ k ^ {|
-----END PUBLIC KEY-----|}

  (* Since openssl 3.0.1 *)
  let verify_ed25519 ~key ~data ~signature id =
    let* signature =
      try Ok (B64.decode signature) with _ -> Error (`InvalidBase64Encoding id)
    in
    Result.map_error (function
        | "broken" -> `InvalidSignature id
        | _ -> `InvalidPublicKey id)
      (let filename = Filename.temp_file "conex" "sig" in
       let key = pem_of_ed25519 key in
       let* () = Conex_unix_persistency.write_replace (filename ^ ".key") key in
       let* () = Conex_unix_persistency.write_replace (filename ^ ".txt") data in
       let* () = Conex_unix_persistency.write_replace (filename ^ ".sig") signature in
       let cmd = Printf.sprintf "openssl pkeyutl -verify -pubin -inkey %s.key -rawin -in %s.txt -sigfile %s.sig > /dev/null" filename filename filename in
       let res = if 0 = Sys.command cmd then Ok () else Error "broken" in
       let _ = Conex_unix_persistency.remove (filename ^ ".txt")
       and _ = Conex_unix_persistency.remove (filename ^ ".key")
       and _ = Conex_unix_persistency.remove (filename ^ ".sig")
       and _ = Conex_unix_persistency.remove filename
       in
       res)

  let sha256 data = Sha256.to_hex (Sha256.string data)
end

module O_V = Conex_verify.Make (V)
