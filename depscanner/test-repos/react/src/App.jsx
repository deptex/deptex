import React, { useEffect, useState } from 'react';
import axios from 'axios';
import _ from 'lodash';

export default function App() {
  const [items, setItems] = useState([]);
  const params = new URLSearchParams(window.location.search);
  const tpl = params.get('tpl') ?? '';

  useEffect(() => {
    // axios usage so tree-sitter records it (reachable).
    axios.get('/api/items').then((r) => setItems(r.data));
  }, []);

  // Reachable lodash sink: _.template with user-tainted tpl string.
  // Mirrors the CVE-2021-23337 shape seeded in the express fixture, but
  // exercised through a client-render trust boundary (React renders the
  // compiled string verbatim).
  const compiled = _.template(tpl);
  const greeting = compiled({ name: 'world' });

  return (
    <main>
      <h1>{greeting}</h1>
      <ul>
        {items.map((i) => (
          <li key={i.id}>{i.label}</li>
        ))}
      </ul>
    </main>
  );
}
