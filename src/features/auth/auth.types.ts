export interface AuthSettings {
  jwtSecret: string;
  verificationSecret: string;
  webOrigin: string;
  apiUrl: string;
  resetPasswordUrl: string;
  secureCookies: boolean;
  providers: {
    google?: { clientId: string; clientSecret: string };
    github?: { clientId: string; clientSecret: string };
  };
}

export type SendMail = (email: string, subject: string, text: string) => Promise<void>;
