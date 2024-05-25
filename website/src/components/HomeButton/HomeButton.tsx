import { Home } from "@mui/icons-material";
import { Button, ButtonProps, styled } from "@mui/material";
import { grey } from "@mui/material/colors";
import { useNavigate } from "react-router-dom";

export const HomeButton = () => {
  const navigate = useNavigate();

  const HomeColorButton = styled(Button)<ButtonProps>(({ theme }) => ({
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
    <HomeColorButton
      onClick={() => navigate("/")}
      className="home-btn"
      variant="contained"
      endIcon={<Home />}
    >
      Home
    </HomeColorButton>
  );
};
