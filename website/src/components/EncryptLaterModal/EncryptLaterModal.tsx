import {
  Box,
  Button,
  FormControl,
  FormControlLabel,
  FormLabel,
  Modal,
  Radio,
  RadioGroup,
} from "@mui/material";
import { useEffect, useState } from "react";
// import { useFilePicker } from "use-file-picker";
import { baseUrl } from "../../services/api";
import { getAuthToken, getPrivateKey } from "../../services/storeAuth";
import { useNavigate } from "react-router-dom";
import "./EncryptLaterModal.css";
import { DateTimePicker, LocalizationProvider } from "@mui/x-date-pickers";
import { AdapterDayjs } from "@mui/x-date-pickers/AdapterDayjs";
import dayjs from "dayjs";
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
}

export const EncryptLaterModal = ({ open, handleClose }: IProps) => {
  // const { openFilePicker, plainFiles, filesContent } = useFilePicker({
  //   multiple: false,
  // });
  const navigate = useNavigate();

  const [file, setFile] = useState<File>();
  // const [fileName, setFileName] = useState("");
  // const [fileContent, setFileContent] = useState("");
  const [cipherMode, setCipherMode] = useState("1");
  const [hmacMode, setHmacMode] = useState("1");
  const [timestamp, setTimestamp] = useState("");

  // useEffect(() => {
  //   if (
  //     filesContent.length &&
  //     filesContent[0].name &&
  //     filesContent[0].content
  //   ) {
  //     setFileName(filesContent[0].name.split(".")[0]);
  //     setFileContent(filesContent[0].content);
  //   }
  // }, [filesContent]);

  // useEffect(() => {
  //   setFile(plainFiles[0]);
  // }, [plainFiles]);

  useEffect(() => {
    if (!open) {
      clearFile();
    }
  }, [open]);

  const clearFile = () => {
    setFile(undefined);
    // setFileName("");
    // setFileContent("");
  };

  const handleChangeTimestamp = (newDate: dayjs.Dayjs | null) => {
    if (newDate) {
      newDate = newDate.add(-newDate.utcOffset(), "minute");

      const day = newDate?.get("D");
      const month = newDate?.get("M");
      const year = newDate?.get("y");
      const hour = newDate?.get("hour");
      const minute = newDate?.get("minute");

      setTimestamp(`${year}-${month + 1}-${day}-${hour}:${minute}`);
    }
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

    if (!file || !cipherMode || !hmacMode) {
      return alert("Fill every field.");
    }

    console.log(file, file.name);

    // const fileToSend = new Blob([fileContent]);

    const privateKey = getPrivateKey();

    if (!privateKey) {
      return alert("Erro ao obter chave privada... Inicie sessao novamente.");
    }

    const signature = await generateDigitalSignature(privateKey, file);

    const formData = new FormData();
    formData.append("data", file, file.name);
    formData.append("sig", new Blob([signature]));
    formData.append("cipher", cipherMode);
    formData.append("hmac", hmacMode);
    formData.append("filename", file.name);
    formData.append("timestamp", timestamp);

    try {
      const req = await fetch(`${baseUrl}/api/later/encrypt`, {
        method: "POST",
        headers: {
          Authorization: `${tokenType} ${token}`,
          "Access-Control-Expose-Headers": "Content-Disposition",
        },
        body: formData,
      });

      const reqBlob = await req.blob();

      if (!reqBlob) {
        return alert("Something went wrong...");
      }

      if (reqBlob.type === "application/json") {
        const jsonRes = JSON.parse(await reqBlob.text());
        return alert(jsonRes.error);
      }

      saveData(reqBlob, file.name + ".zip");

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
        <h1>Encrypt a file later</h1>

        <div className="file-to-encrypt-div">
          <p>File to encrypt</p>

          <input
            type="file"
            onChange={(file) => {
              if (file.target.files?.length) {
                setFile(file.target.files[0]);
              }
            }}
          />

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

        <FormControl style={{ margin: "30px 0" }}>
          <FormLabel>Cipher mode</FormLabel>
          <RadioGroup
            onChange={(newValue) => setCipherMode(newValue.target.value)}
            defaultValue="1"
            name="radio-buttons-group"
          >
            <FormControlLabel
              value="1"
              control={<Radio />}
              label="AES-128-CBC"
            />
            <FormControlLabel
              value="2"
              control={<Radio />}
              label="AES-128-CTR"
            />
          </RadioGroup>
        </FormControl>

        <FormControl>
          <FormLabel>HMAC mode</FormLabel>
          <RadioGroup
            onChange={(newValue) => setHmacMode(newValue.target.value)}
            defaultValue="1"
            name="radio-buttons-group"
          >
            <FormControlLabel
              value="1"
              control={<Radio />}
              label="HMAC-SHA256"
            />
            <FormControlLabel
              value="2"
              control={<Radio />}
              label="HMAC-SHA512"
            />
          </RadioGroup>
        </FormControl>

        <div className="timestamp-div">
          <p style={{ marginBottom: 5 }}>Date and time to decrypt</p>
          <LocalizationProvider dateAdapter={AdapterDayjs}>
            <DateTimePicker onChange={handleChangeTimestamp} ampm={false} />
          </LocalizationProvider>
        </div>

        <Button
          style={{ alignSelf: "center" }}
          color="success"
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
