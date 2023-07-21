import { randomBytes, createHash } from "crypto";
import { AES, enc } from "crypto-js";

const secret = "LNDsecrethttpsonly";
const initials = "LndevsBlogAdminGUI";

class Session {
  private static instance: Session;
  private token: string;
  private tokenExpiry: Date;

  private constructor() {
    this.token = "";
    this.tokenExpiry = new Date();
  }

  public static getInstance(): Session {
    if (!Session.instance) {
      Session.instance = new Session();
    }
    return Session.instance;
  }

  private generateRandomBytes(size: number): string {
    return randomBytes(size).toString("hex");
  }

  private generateHash(data: string): string {
    return createHash("sha256").update(data).digest("hex");
  }

  private encrypt(param: string): string {
    return AES.encrypt(param, secret).toString();
  }

  private genString(validityDurationMinutes: number = 30): { token: string; expiry: Date } {
    const randomPart = this.generateRandomBytes(16);
    const timestampPart = new Date().getTime().toString();
    const expiry = new Date(new Date().getTime() + validityDurationMinutes * 60000); // Convert minutes to milliseconds
    const tokenString = `${this.encrypt(initials)}.${this.encrypt(
      `LoggedIn${timestampPart}ViaWebGUI${randomPart}`
    )}`;
    return { token: tokenString, expiry };
  }

  public newToken(validityDurationMinutes?: number): { token: string; expiry: Date } {
    const { token, expiry } = this.genString(validityDurationMinutes);
    this.token = token;
    this.tokenExpiry = expiry;
    return { token, expiry };
  }

  public verifyToken(token: string): boolean {
    const [encryptedInitials, encryptedData] = token.split(".");
    if (encryptedInitials === this.encrypt(initials)) {
      const decryptedData = AES.decrypt(encryptedData, secret).toString(enc.Utf8);
      const parts = decryptedData.split("ViaWebGUI");
      if (parts.length === 2) {
        const timestampPart = parts[0].replace("LoggedIn", "");
        const timestamp = parseInt(timestampPart);
        // Add validation for token expiration if necessary
        return !isNaN(timestamp);
      }
    }
    return false;
  }
}
