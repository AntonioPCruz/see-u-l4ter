import { Button, ButtonProps, TextField, styled } from "@mui/material";
import { AuthButtons } from "../../components/authButtons/authButtons";
import { VpnKey } from "@mui/icons-material";
import "./Login.css";
import { useNavigate } from "react-router-dom";
import { useState } from "react";
import { baseUrl } from "../../services/api";
import { saveAuthToken } from "../../services/storeAuth";
import { grey } from "@mui/material/colors";
import { HomeButton } from "../../components/HomeButton/HomeButton";
import { generateRsaKeyPair } from "../../services/generateDigitalSignature";

export const Login = () => {
  const navigate = useNavigate();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  const handleLogin = async () => {
    if (!email || !password) {
      return alert("Preencha todos os campos!");
    }

    const { publicKey, error: RsaError } = await generateRsaKeyPair();

    if (RsaError) {
      return alert(RsaError);
    }

    const req = await fetch(`${baseUrl}/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        email,
        pk: publicKey,
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

  const LoginColorButton = styled(Button)<ButtonProps>(({ theme }) => ({
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

        <AuthButtons auth="login" />
      </nav>

      <div className="login-div">
        <div className="login-title-div">
          <h1>SEE-U-L4TER</h1>
          <p>Welcome back</p>
        </div>

        <div className="login-text-field-div">
          <TextField
            value={email}
            onChange={(text) => setEmail(text.target.value)}
            className="login-text-field"
            label="Email"
            variant="outlined"
          />

          <TextField
            value={password}
            onChange={(text) => setPassword(text.target.value)}
            className="login-text-field"
            label="Password"
            variant="outlined"
            type="password"
          />
        </div>

        <LoginColorButton
          onClick={handleLogin}
          className="login-btn"
          variant="outlined"
          startIcon={<VpnKey />}
        >
          LOGIN
        </LoginColorButton>
      </div>
    </main>
  );
};
