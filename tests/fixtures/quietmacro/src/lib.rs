//! A proc-macro that does nothing dangerous, and exists to be NOT named.
//!
//! Attribution's hard promise is not just that it can name a macro, but that it names the
//! RIGHT one. That is only demonstrable when there is a wrong one in the same closure. This
//! fixture is the wrong one: it expands to nothing and issues no syscall, so no instruction
//! pointer ever falls inside `libquietmacro-*.so`. It must appear in the closure set that a
//! refusal records — it really is a proc-macro the compilation loaded — and it must never
//! appear as the `exact` attribution of a request it had no part in. A tool that named it
//! would be making an accusation on the user's behalf that nothing established.

use proc_macro::TokenStream;

#[proc_macro_derive(Quiet)]
pub fn quiet(_item: TokenStream) -> TokenStream {
    TokenStream::new()
}
