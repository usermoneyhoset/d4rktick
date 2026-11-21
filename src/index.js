export default {
  fetch(request, env, ctx) {
    return new Response("D4rk Tickets API is online!", {
      status: 200,
      headers: {
        "Content-Type": "text/plain"
      }
    });
  }
};
