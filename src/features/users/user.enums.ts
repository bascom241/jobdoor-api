export enum UserRole {
  User = 'user',
  Candidate = 'candidate',
}

// Onboarding intent does not grant organisation or administrative permissions.
export enum UserType {
  JobSeeker = 'job_seeker',
  Employer = 'employer',
  Recruiter = 'recruiter',
  Freelancer = 'freelancer',
  Employee = 'employee',
  ManagerHrAdmin = 'manager_hr_admin',
}

export enum AccountStatus {
  PendingVerification = 'pending_verification',
  Active = 'active',
}
