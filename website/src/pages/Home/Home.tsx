import "./Home.css";
import { AuthButtons } from "../../components/authButtons/authButtons";

function App() {
  return (
    <main>
      <AuthButtons />

      <div className="main-title-div">
        <h1>SEE-U-L4TER</h1>
        <h2>A cryptographic time capsule</h2>
      </div>
    </main>
  );
}

export default App;
