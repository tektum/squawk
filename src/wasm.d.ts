declare module "*.wasm" {
  const module: WebAssembly.Module;
  export default module;
}

declare module "./generated/wasm_exec.js";

declare class Go {
  readonly importObject: WebAssembly.Imports;
  run(instance: WebAssembly.Instance): Promise<void>;
}
