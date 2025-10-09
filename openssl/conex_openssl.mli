(** Verification crypto provided by the OpenSSL command line tool *)

module V : sig

  (** [check_openssl ()] checks the openssl version (required: >= 1.0.0). *)
  val check_version : unit -> (unit, string) result

  include Conex_verify.S_BACK
end

(** The instantiaed verify module *)
module O_V : (Conex_verify.S)
