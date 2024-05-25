import { Box, Button, IconButton, Modal } from "@mui/material";
import { useEffect, useState } from "react";
import { baseUrl } from "../../services/api";
import { getAuthToken } from "../../services/storeAuth";
import { useNavigate } from "react-router-dom";
import "./OldKeysModal.css";
import { DateTimePicker, LocalizationProvider } from "@mui/x-date-pickers";
import { AdapterDayjs } from "@mui/x-date-pickers/AdapterDayjs";
import dayjs from "dayjs";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faCopy } from "@fortawesome/free-regular-svg-icons";

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

export const OldKeysModal = ({ open, handleClose }: IProps) => {
  const navigate = useNavigate();

  const [timestamp, setTimestamp] = useState("");
  const [oldKey, setOldKey] = useState("");

  const handleChangeTimestamp = (newDate: dayjs.Dayjs | null) => {
    if (newDate) {
      const day = newDate?.get("D");
      const month = newDate?.get("M");
      const year = newDate?.get("y");
      const hour = newDate?.get("hour");
      const minute = newDate?.get("m");

      setTimestamp(`${year}-${month + 1}-${day}-${hour}:${minute}`);
    }
  };

  useEffect(() => {
    if (!open) {
      setTimestamp("");
    }
  }, [open]);

  const onSubmit = async () => {
    const { tokenType, token } = getAuthToken();

    if (!tokenType || !token) {
      handleSignOut();
      return navigate("/login");
    }

    const formData = new FormData();
    formData.append("timestamp", timestamp);

    try {
      const req = await fetch(`${baseUrl}/api/old/gen`, {
        method: "POST",
        headers: {
          Authorization: `${tokenType} ${token}`,
        },
        body: formData,
      });

      const reqData = await req.json();

      const { key, error } = reqData;

      if (error || !key) {
        return alert(error || "Something went wrong");
      }

      setOldKey(key);

      // handleClose();
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
        <h1>Generate Old Keys</h1>

        <div className="timestamp-div">
          <p style={{ marginBottom: 5 }}>Date and time to decrypt</p>
          <LocalizationProvider dateAdapter={AdapterDayjs}>
            <DateTimePicker onChange={handleChangeTimestamp} ampm={false} />
          </LocalizationProvider>
        </div>

        <Button
          color="success"
          style={{ marginTop: 20, alignSelf: "center" }}
          onClick={onSubmit}
          variant="contained"
        >
          Submit
        </Button>

        {oldKey && (
          <div className="oldkey-div">
            <h3>Generated key</h3>

            <div className="oldkey-div__container">
              <p>{oldKey}</p>

              <IconButton
                className="copy-btn"
                onClick={() => navigator.clipboard.writeText(oldKey)}
                aria-label="Example"
              >
                <FontAwesomeIcon icon={faCopy} />
              </IconButton>
            </div>
          </div>
        )}
      </Box>
    </Modal>
  );
};
function handleSignOut() {
  throw new Error("Function not implemented.");
}
