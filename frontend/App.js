import { useState } from 'react';

function Counter() {
  const [count, setCount] = useState(0);

  return (
    <div style={{ padding: '40px', textAlign: 'center', fontFamily: 'sans-serif' }}>
      <h1>Counter: {count}</h1>
      <button onClick={() => setCount(count + 1)}>Click Me +</button>
    </div>
  );
}

function MyForm() {
  const [text, setText] = useState('');

  return (
    <div style={{ padding: '40px', fontFamily: 'sans-serif' }}>
      <h2>Type Something:</h2>
      <input
        type="text"
        value={text}
        onChange={(e) => setText(e.target.value)}
        placeholder="Type here..."
      />
      <p>You typed: <strong>{text}</strong></p>
    </div>
  );
}

function App() {
  return (
    <div>
      <Counter />
      <MyForm />
    </div>
  );
}

export default App;