open Conex_utils

(** Data provider using an existing provider and a diff *)

val apply : Conex_io.t -> Patch.t list -> Conex_io.t

val apply_diff : Conex_io.t -> string -> (Conex_io.t * Patch.t list)

(** [ids rootname keydir diffs] returns whether the root file was changed, and
    the set of modified ids. *)
val ids : string -> path -> Patch.t list -> (bool * S.t, string) result
