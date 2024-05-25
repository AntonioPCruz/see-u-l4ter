import { LockOpen, PersonAdd } from "@mui/icons-material";
import { Button, ButtonProps, styled } from "@mui/material";
import { grey } from "@mui/material/colors";
import { useNavigate } from "react-router-dom";

interface IProps {
  auth?: "login" | "register" | undefined;
}

export const AuthButtons = ({ auth }: IProps) => {
  const navigate = useNavigate();

  const goToLogin = () => {
    navigate("/login");
  };

  const goToRegister = () => {
    navigate("/register");
  };

  const LoginColorButton = styled(Button)<ButtonProps>(({ theme }) => ({
    color: grey[900],
    borderColor: grey[900],
    "&:hover": {
      color: grey[900],
      borderColor: grey[900],
      backgroundColor: grey[200],
    },
    "&:disabled": {
      color: grey[500],
      borderColor: grey[500],
    },
  }));

  const RegisterColorButton = styled(Button)<ButtonProps>(({ theme }) => ({
    color: theme.palette.getContrastText(grey[900]),
    backgroundColor: grey[900],
    "&:hover": {
      backgroundColor: grey["900"],
      color: theme.palette.getContrastText(grey[900]),
    },
    "&:disabled": {
      backgroundColor: grey["A100"],
    },
  }));

  return (
    <div className="auth-buttons-div">
      <LoginColorButton
        className="auth-btn"
        disabled={auth === "login"}
        variant="outlined"
        startIcon={<LockOpen />}
        onClick={goToLogin}
      >
        LOGIN
      </LoginColorButton>

      <RegisterColorButton
        disabled={auth === "register"}
        className="auth-btn"
        variant="contained"
        startIcon={<PersonAdd />}
        onClick={goToRegister}
      >
        REGISTER
      </RegisterColorButton>
    </div>
  );
};
