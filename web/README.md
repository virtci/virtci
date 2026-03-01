# How Does This Web Chicanery Work

In one terminal run:

```sh
cargo run -- serve
```

In another, run:

```sh
cd web
npm run dev
```

Any `api/` requests the Vite dev server makes will be routed to the Rust backend running on whichever port. That is seen in `vite.config.ts` with the `proxy` settings.
