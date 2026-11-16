export enum AuthEventType {
  RegistrationSucceeded = 'registration_succeeded',
  LoginSucceeded = 'login_succeeded',
  EmailVerified = 'email_verified',
  PasswordReset = 'password_reset',
  Logout = 'logout',
  OnboardingCompleted = 'onboarding_completed',
}

export enum AuthProvider {
  Google = 'google',
  GitHub = 'github',
}
