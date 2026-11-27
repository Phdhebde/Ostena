import "./app.css";
import { mount } from "svelte";
import App from "./App.svelte";

const target = document.getElementById("app");
if (target === null) {
  throw new Error("élément #app absent de index.html");
}
mount(App, { target });
