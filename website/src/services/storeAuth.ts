export const saveAuthToken = (tokenType: any, token: any) => {
  localStorage.setItem("tokenType", tokenType);
  localStorage.setItem("token", token);
};

export const deleteAuthToken = () => {
  localStorage.removeItem("token");
  localStorage.removeItem("tokenType");
};

export const getAuthToken = () => {
  const tokenType = localStorage.getItem("tokenType") || "";
  const token = localStorage.getItem("token") || "";

  return {
    tokenType,
    token,
  };
};

export const storePrivateKey = (privateKey: JsonWebKey) => {
  localStorage.setItem("privateKey", JSON.stringify(privateKey));
};

export const getPrivateKey = (): JsonWebKey => {
  return JSON.parse(localStorage.getItem("privateKey") || "{}");
};

export const storePublicKey = (publicKey: string) => {
  localStorage.setItem("publicKey", publicKey);
};

export const getPublicKey = () => {
  return localStorage.getItem("publicKey");
};
