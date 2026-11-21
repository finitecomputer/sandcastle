// The home study's Worker (docs/nitro-spike.md, "A home"): the smallest
// application with one Durable Object. GET reads an object's counter, POST
// adds one; `?name=` picks the object. A read after a restore shows what an
// earlier life last acknowledged.
export class Counter {
  constructor(state) {
    this.state = state;
  }
  async fetch(request) {
    if (request.method === "POST") {
      const n = ((await this.state.storage.get("n")) ?? 0) + 1;
      await this.state.storage.put("n", n);
      return Response.json({ n });
    }
    return Response.json({ n: (await this.state.storage.get("n")) ?? 0 });
  }
}

export default {
  async fetch(request, env) {
    const name = new URL(request.url).searchParams.get("name") ?? "default";
    return env.COUNTER.get(env.COUNTER.idFromName(name)).fetch(request);
  },
};
