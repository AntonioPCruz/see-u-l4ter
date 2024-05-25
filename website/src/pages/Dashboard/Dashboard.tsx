import { Button, ButtonProps, IconButton, Stack, styled } from "@mui/material";
import {
  ExitToApp,
  Lock,
  WatchLater,
  LockOpen,
  VpnKey,
} from "@mui/icons-material";
import "./Dashboard.css";
import { useEffect, useState } from "react";
import { deleteAuthToken, getAuthToken } from "../../services/storeAuth";
import { useNavigate } from "react-router-dom";
import { baseUrl } from "../../services/api";
import { EncryptNowModal } from "../../components/EncryptNowModal/EncryptNowModal";
import { EncryptLaterModal } from "../../components/EncryptLaterModal/EncryptLaterModal";
import { DecryptModal } from "../../components/DecryptModal/DecryptModal";
import { OldKeysModal } from "../../components/OldKeysModal/OldKeysModal";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faCopy } from "@fortawesome/free-regular-svg-icons";
import { grey } from "@mui/material/colors";

export interface UserProfile {
  name: string;
  email: string;
}

export const Dashboard = () => {
  const navigate = useNavigate();

  const [currentKey, setCurrentKey] = useState("A obter a chave...");
  const [userProfile, setUserProfile] = useState<UserProfile>();
  const [modalState, setModalState] = useState<
    "encrypt_now" | "encrypt_later" | "decrypt" | "old_keys" | null
  >(null);

  const handleSignOut = () => {
    deleteAuthToken();
    navigate("/login");
  };

  const handleOpenEncryptNowModal = () => setModalState("encrypt_now");
  const handleOpenEncryptLaterModal = () => setModalState("encrypt_later");
  const handleOpenDecryptModal = () => setModalState("decrypt");
  const handleOpenOldKeysModal = () => setModalState("old_keys");

  const handleCloseModal = () => setModalState(null);

  useEffect(() => {
    const fetchData = async () => {
      const { tokenType, token } = getAuthToken();

      if (!tokenType || !token) {
        handleSignOut();
        return navigate("/login");
      }

      const reqKey = await fetch(`${baseUrl}/api/now/gen`, {
        method: "POST",
        headers: {
          Authorization: `${tokenType} ${token}`,
        },
      });

      const { key } = await reqKey.json();

      if (key) {
        setCurrentKey(key);
      }

      const req = await fetch(`${baseUrl}/profile`, {
        method: "GET",
        headers: {
          Authorization: `${tokenType} ${token}`,
        },
      });

      const data = await req.json();

      const { name, email } = data;

      if (!name || !email) {
        handleSignOut();
        return navigate("/login");
        // ToDo: REMOVE COMMENT
        // return alert("Something went wrong...");
      }

      setUserProfile({
        name: name,
        email: email,
      });
    };

    fetchData();
  }, []);

  const ColorButton = styled(Button)<ButtonProps>(({ theme }) => ({
    color: theme.palette.getContrastText(grey[900]),
    backgroundColor: grey[900],
    "&:hover": {
      borderColor: grey[900],
      backgroundColor: grey["200"],
      color: theme.palette.getContrastText(grey[200]),
    },
  }));

  return (
    <main className="dashboard-main">
      <EncryptNowModal
        handleClose={handleCloseModal}
        open={modalState === "encrypt_now"}
      />

      <EncryptLaterModal
        handleClose={handleCloseModal}
        open={modalState === "encrypt_later"}
      />

      <DecryptModal
        userProfile={userProfile}
        handleClose={handleCloseModal}
        open={modalState === "decrypt"}
      />

      <OldKeysModal
        handleClose={handleCloseModal}
        open={modalState === "old_keys"}
      />

      <header>
        <div className="header-title-div">
          <h1>SEE-U-L4TER</h1>
          <p>A cryptographic time capsule</p>
        </div>

        <div className="currentkey-div">
          <h3>Current key</h3>

          <p>{currentKey}</p>

          <IconButton
            className="copy-btn"
            onClick={() => navigator.clipboard.writeText(currentKey)}
            aria-label="Example"
          >
            <FontAwesomeIcon icon={faCopy} />
          </IconButton>
        </div>

        <div className="header-user-div">
          <p>Hello, {userProfile?.name}</p>

          <Button
            onClick={handleSignOut}
            color="error"
            variant="contained"
            startIcon={<ExitToApp />}
          >
            Sign out
          </Button>
        </div>
      </header>

      <Stack style={{ marginTop: 50, padding: "0 50px" }} spacing={2}>
        <ColorButton
          onClick={handleOpenEncryptNowModal}
          className="dashboard-div-btn"
          color="error"
          variant="contained"
          startIcon={<Lock />}
        >
          Encrypt now
        </ColorButton>

        <ColorButton
          onClick={handleOpenEncryptLaterModal}
          className="dashboard-div-btn"
          color="error"
          variant="contained"
          startIcon={<WatchLater />}
        >
          Encrypt later
        </ColorButton>

        <ColorButton
          onClick={handleOpenDecryptModal}
          className="dashboard-div-btn"
          color="error"
          variant="contained"
          startIcon={<LockOpen />}
        >
          Decrypt
        </ColorButton>

        <ColorButton
          onClick={handleOpenOldKeysModal}
          className="dashboard-div-btn"
          color="error"
          variant="contained"
          startIcon={<VpnKey />}
        >
          Old keys
        </ColorButton>
      </Stack>

      {/* <div className="dashboard-div">


        <Button
          onClick={handleOpenEncryptNowModal}
          className="dashboard-div-btn"
          color="error"
          variant="contained"
          startIcon={<Lock />}
        >
          Encrypt now
        </Button>

        <Button
          onClick={handleOpenEncryptLaterModal}
          className="dashboard-div-btn"
          color="error"
          variant="contained"
          startIcon={<WatchLater />}
        >
          Encrypt later
        </Button>

        <Button
          onClick={handleOpenDecryptModal}
          className="dashboard-div-btn"
          color="error"
          variant="contained"
          startIcon={<LockOpen />}
        >
          Decrypt
        </Button>

        <Button
          onClick={handleOpenOldKeysModal}
          className="dashboard-div-btn"
          color="error"
          variant="contained"
          startIcon={<VpnKey />}
        >
          Old keys
        </Button>
      </div> */}
    </main>
  );
};
