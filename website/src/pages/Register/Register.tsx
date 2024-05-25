import { Button, ButtonProps, TextField, styled } from "@mui/material";
import { AuthButtons } from "../../components/authButtons/authButtons";
import { VpnKey } from "@mui/icons-material";
import "./Register.css";
import { useNavigate } from "react-router-dom";
import { useState } from "react";
import { baseUrl } from "../../services/api";
import { saveAuthToken } from "../../services/storeAuth";
import { HomeButton } from "../../components/HomeButton/HomeButton";
import { grey } from "@mui/material/colors";
import { generateRsaKeyPair } from "../../services/generateDigitalSignature";

export const Register = () => {
  const navigate = useNavigate();

  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [repeatPassword, setRepeatPassword] = useState("");

  const handleRegister = async () => {
    if (!name || !email || !password || !repeatPassword) {
      return alert("Fill in every field.");
    }

    if (password !== repeatPassword) {
      return alert("Passwords don't match!");
    }

    const { publicKey, error: RsaError } = await generateRsaKeyPair();

    if (RsaError) {
      return alert(RsaError);
    }

    const req = await fetch(`${baseUrl}/register`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        name,
        pk: publicKey,
        email,
        client_secret: password,
      }),
    });

    const data = await req.json();

    const { error, access_token, token_type } = data;

    if (error || !access_token || !token_type) {
      return alert("Error: " + error || "Something went wrong...");
    }

    saveAuthToken(token_type, access_token);
    navigate("/dashboard");
  };

  const RegisterColorButton = styled(Button)<ButtonProps>(({ theme }) => ({
    color: grey[900],
    borderColor: grey[900],
    "&:hover": {
      color: theme.palette.getContrastText(grey[900]),
      borderColor: grey[900],
      backgroundColor: grey[900],
    },
    "&:disabled": {
      color: grey[500],
      borderColor: grey[500],
    },
  }));

  return (
    <main>
      <nav className="auth-navbar">
        <HomeButton />

        <AuthButtons auth="register" />
      </nav>

      <div className="auth-div">
        <div className="auth-title-div">
          <h1>SEE-U-L4TER</h1>
          <p>Welcome</p>
        </div>

        <div className="auth-text-field-div">
          <TextField
            className="auth-text-field"
            label="Name"
            variant="outlined"
            value={name}
            onChange={(event) => setName(event.target.value)}
          />

          <TextField
            className="auth-text-field"
            label="Email"
            variant="outlined"
            type="email"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
          />

          <TextField
            className="auth-text-field"
            label="Password"
            variant="outlined"
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
          />

          <TextField
            className="auth-text-field"
            label="Confirm password"
            variant="outlined"
            type="password"
            value={repeatPassword}
            onChange={(event) => setRepeatPassword(event.target.value)}
          />
        </div>

        <RegisterColorButton
          onClick={handleRegister}
          className="auth-btn"
          variant="outlined"
          startIcon={<VpnKey />}
        >
          REGISTER
        </RegisterColorButton>
      </div>
    </main>
  );
};
