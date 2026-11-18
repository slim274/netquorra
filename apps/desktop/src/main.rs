use dioxus::prelude::*;
use ui::Dashboard;

fn main() {
    dioxus::launch(App);
}

#[component]
fn App() -> Element {
    rsx! {
        Dashboard {}
    }
}