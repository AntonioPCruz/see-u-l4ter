import { Box, Button, Modal, TextField } from "@mui/material";
import { useEffect, useState } from "react";
import { useFilePicker } from "use-file-picker";
import { baseUrl } from "../../services/api";
import { getAuthToken, getPrivateKey } from "../../services/storeAuth";
import { useNavigate } from "react-router-dom";
import "./DecryptModal.css";
import { UserProfile } from "../../pages/Dashboard/Dashboard";
import { generateDigitalSignature } from "../../services/generateDigitalSignature";

const style = {
  position: "absolute" as "absolute",
  top: "50%",
  left: "50%",
  transform: "translate(-50%, -50%)",
  width: 400,
  bgcolor: "background.paper",
  border: "2px solid #000",
  boxShadow: 24,
  p: 4,
};

interface IProps {
  open: boolean;
  handleClose: () => void;
  userProfile: UserProfile | undefined;
}

export const DecryptModal = ({ open, handleClose, userProfile }: IProps) => {
  const { openFilePicker, plainFiles } = useFilePicker({
    multiple: false,
    accept: ".zip",
  });
  const navigate = useNavigate();

  const [file, setFile] = useState<File>();
  const [email, setEmail] = useState("");

  useEffect(() => {
    setFile(plainFiles[0]);
  }, [plainFiles]);

  useEffect(() => {
    if (!open) {
      clearFile();
      setEmail("");
    }
  }, [open]);

  const clearFile = () => {
    setFile(undefined);
  };

  const saveData = (function () {
    var a = document.createElement("a") as any;
    document.body.appendChild(a);
    a.style = "display: none";
    return function (data: any, fileName: string) {
      // var json = JSON.stringify(data);
      // var blob = new Blob([json], { type: "octet/stream" });
      var url = window.URL.createObjectURL(data);

      a.href = url;
      a.download = fileName;
      a.click();
      window.URL.revokeObjectURL(url);
    };
  })();

  const onSubmit = async () => {
    const { tokenType, token } = getAuthToken();

    if (!tokenType || !token) {
      handleSignOut();
      return navigate("/login");
    }

    if (!file) {
      return alert("Select a file.");
    }

    let targetEmail = email;

    if (!email) {
      targetEmail = userProfile?.email || "";
    }

    if (!targetEmail) {
      handleSignOut();
      return navigate("/login");
    }

    const privateKey = getPrivateKey();

    if (!privateKey) {
      return alert("Erro ao obter chave privada... Inicie sessao novamente.");
    }

    const signature = await generateDigitalSignature(privateKey, file);

    const formData = new FormData();
    formData.append("data", file);
    formData.append("sig", new Blob([signature]));
    formData.append("email", targetEmail);

    try {
      const req = await fetch(`${baseUrl}/api/now/decrypt`, {
        method: "POST",
        headers: {
          Authorization: `${tokenType} ${token}`,
          "Access-Control-Expose-Headers": "Content-Disposition",
          "Accept-Encoding": "gzip, deflate, br",
        },
        body: formData,
      });

      const reqBlob = await req.blob();

      if (!reqBlob) {
        return alert("Something went wrong...");
      }

      // const fileName = file.name;
      // const index = fileName.lastIndexOf(".");
      // fileName.
      // imagem.zip
      // imagem.decoded.zip

      saveData(reqBlob, file.name + ".decoded.zip");

      // const blobUrl = window.URL.createObjectURL(reqBlob);
      // window.location.assign(blobUrl);

      handleClose();
    } catch (error) {
      console.error(error);

      return alert("Something went wrong...");
    }
  };

  return (
    <Modal
      open={open}
      onClose={handleClose}
      aria-labelledby="modal-modal-title"
      aria-describedby="modal-modal-description"
    >
      <Box
        className="encrypt-now-modal-box"
        style={{
          display: "flex",
          justifyContent: "center",
          alignItems: "flex-start",
          flexDirection: "column",
        }}
        sx={style}
      >
        <h1>Decrypt an encrypted file</h1>

        <div className="file-to-encrypt-div">
          <p>File to encrypt</p>

          <Button
            className="file-to-encrypt-div__pick-file-btn"
            variant="contained"
            onClick={openFilePicker}
          >
            Open file
          </Button>

          {file?.name && (
            <div>
              <p className="file-to-encrypt-div__file-name">
                Selected file: <span>{file.name}</span>
              </p>

              <Button
                onClick={clearFile}
                className="file-to-encrypt-div__clear-btn"
                variant="contained"
                color="error"
              >
                Clear selection
              </Button>
            </div>
          )}
        </div>

        <TextField
          style={{ marginTop: 20 }}
          type="email"
          placeholder="(Optional) Email"
          onChange={(newValue) => setEmail(newValue.target.value)}
        />

        <Button
          color="success"
          style={{ marginTop: 20, alignSelf: "center" }}
          onClick={onSubmit}
          variant="contained"
        >
          Submit
        </Button>
      </Box>
    </Modal>
  );
};
function handleSignOut() {
  throw new Error("Function not implemented.");
}
