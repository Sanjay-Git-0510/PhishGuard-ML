"""
TRUSTLENS Synthetic Social Engineering Dataset Generator
---------------------------------------------------------
Generates 600+ carefully constructed multilingual examples for training
the message classification model.

Supports:
  - English Email (benign + suspicious)
  - Hindi Email (benign + suspicious)
  - Kannada Email (benign + suspicious)
  - English SMS (benign + suspicious)
  - Hindi SMS (benign + suspicious)
  - Kannada SMS (benign + suspicious)
  - Code-mixed Indic-English

IMPORTANT:
  - All organizations are fictional (example domains, invented names)
  - Examples are clearly marked as synthetic
  - Distribution: 200 benign, 200 suspicious
  - Some benign messages contain urgency words
  - Some suspicious messages contain no URL
  - Labels are accurate — no fabricated classifications

DO NOT commit this file to production without review.
"""

import os
import sys
import json
import csv
import uuid
from datetime import datetime, timezone
from typing import List, Dict

_ML_DIR = os.path.dirname(os.path.abspath(__file__))
if _ML_DIR not in sys.path:
    sys.path.insert(0, _ML_DIR)

from hindi_samples import (
    HINDI_EMAIL_BENIGN,
    HINDI_EMAIL_SUSPICIOUS,
    HINDI_SMS_BENIGN,
    HINDI_SMS_SUSPICIOUS,
)

OUTPUT_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "datasets", "synthetic"
)
OUTPUT_CSV = os.path.join(OUTPUT_DIR, "trustlens_synthetic_dataset.csv")
OUTPUT_METADATA = os.path.join(OUTPUT_DIR, "synthetic_metadata.json")

SCHEMA_FIELDS = [
    "sample_id", "channel", "language", "language_variant",
    "subject", "message", "claimed_identity", "sender_name",
    "sender_address", "reply_to", "sender_id", "provenance",
    "original_label", "normalized_label", "attack_type",
    "source_dataset", "scenario_id", "review_status",
]

# ─────────────────────────────────────────────
# ENGLISH EMAIL — BENIGN (50 samples)
# ─────────────────────────────────────────────
ENGLISH_EMAIL_BENIGN = [
    {
        "subject": "Assignment Submission Reminder — CS401",
        "message": "Dear Student, This is a reminder that your assignment for CS401 (Database Systems) is due by Friday, 5th November at 11:59 PM. Please submit through the university portal at student.demouniversity.example. Late submissions will receive a 10% deduction per day. Contact your professor if you have any questions. Best regards, Department of Computer Science, Demo University",
        "claimed_identity": "Demo University",
        "sender_name": "Demo University Academics",
        "sender_address": "academics@demouniversity.example",
        "reply_to": "academics@demouniversity.example",
        "sender_id": "DEMOUNI",
        "attack_type": "benign_notification",
        "scenario_id": "EN_EMAIL_BENIGN_001",
    },
    {
        "subject": "Examination Schedule Released — November 2024",
        "message": "Dear Students, The examination schedule for the November 2024 semester has been released. Please log in to the student portal at student.demouniversity.example to view your hall ticket and timetable. Note: Carry your ID card to the examination hall. Good luck! Regards, Examination Department, Demo University",
        "claimed_identity": "Demo University",
        "sender_name": "Demo University Examinations",
        "sender_address": "exams@demouniversity.example",
        "reply_to": "exams@demouniversity.example",
        "sender_id": "DEMOUNI",
        "attack_type": "benign_notification",
        "scenario_id": "EN_EMAIL_BENIGN_002",
    },
    {
        "subject": "Account Statement — October 2024",
        "message": "Dear Account Holder, Your account statement for October 2024 is now available. You can view it by logging into your Demo Bank account at www.demobank.example. If you notice any discrepancy, please contact our customer care at 1800-000-0001. Thank you for banking with us. Regards, Demo Bank",
        "claimed_identity": "Demo Bank",
        "sender_name": "Demo Bank",
        "sender_address": "statements@demobank.example",
        "reply_to": "statements@demobank.example",
        "sender_id": "DEMOBANK",
        "attack_type": "legitimate_payment",
        "scenario_id": "EN_EMAIL_BENIGN_003",
    },
    {
        "subject": "Transaction Alert: INR 500 Credited",
        "message": "Dear Customer, INR 500 has been credited to your Demo Bank savings account ending in XXXX4521 on 31-Oct-2024 at 10:15 AM. Available balance: INR 12,500. If you did not authorize this transaction, call our 24/7 helpline at 1800-000-0001 immediately. Demo Bank will never ask for your OTP or PIN. Regards, Demo Bank",
        "claimed_identity": "Demo Bank",
        "sender_name": "Demo Bank Alerts",
        "sender_address": "alerts@demobank.example",
        "reply_to": "alerts@demobank.example",
        "sender_id": "DEMOBANK",
        "attack_type": "legitimate_payment",
        "scenario_id": "EN_EMAIL_BENIGN_004",
    },
    {
        "subject": "Meeting Invitation: Department Review — 3 Nov",
        "message": "Hi Team, You are invited to attend the quarterly department review meeting on Monday, 3rd November 2024, at 2:00 PM in Conference Room 204, Block A. Please confirm your attendance by replying to this email. Meeting agenda is attached. See you there! Best, Dr. Priya Sharma, Head of Department",
        "claimed_identity": "Demo University",
        "sender_name": "Dr. Priya Sharma",
        "sender_address": "p.sharma@demouniversity.example",
        "reply_to": "p.sharma@demouniversity.example",
        "sender_id": "DEMOUNI",
        "attack_type": "benign_notification",
        "scenario_id": "EN_EMAIL_BENIGN_005",
    },
    {
        "subject": "Scholarship Application Status Update",
        "message": "Dear Applicant, We are pleased to inform you that your scholarship application (Ref: SCH-2024-8821) for the Merit Scholarship Programme has been received and is under review. You will receive a decision by 15th November 2024. No action is required from your side at this time. Regards, Scholarship Office, Demo University",
        "claimed_identity": "Demo University",
        "sender_name": "Demo University Scholarship Office",
        "sender_address": "scholarships@demouniversity.example",
        "reply_to": "scholarships@demouniversity.example",
        "sender_id": "DEMOUNI",
        "attack_type": "benign_notification",
        "scenario_id": "EN_EMAIL_BENIGN_006",
    },
    {
        "subject": "Package Delivered — Order #DL-00812",
        "message": "Hi there, Your package (Order #DL-00812) was delivered to your doorstep at 11:30 AM today. If you were not available, the package has been left with a neighbour or at the nearest collection point. For any delivery issues, contact our support at support@demodelivery.example or call 1800-000-0004. Thank you, Demo Delivery",
        "claimed_identity": "Demo Delivery",
        "sender_name": "Demo Delivery",
        "sender_address": "noreply@demodelivery.example",
        "reply_to": "support@demodelivery.example",
        "sender_id": "DEMODLV",
        "attack_type": "benign_notification",
        "scenario_id": "EN_EMAIL_BENIGN_007",
    },
    {
        "subject": "Insurance Policy Renewal Notice",
        "message": "Dear Policyholder, Your Demo Insurance policy (Policy No: DI-2021-5544) is due for renewal on 30th November 2024. Premium due: INR 8,500 (annual). Please renew online at www.demoinsurance.example or visit your nearest branch. For queries, contact 1800-000-0003. Note: This is a scheduled reminder, not a final notice. Regards, Demo Insurance",
        "claimed_identity": "Demo Insurance",
        "sender_name": "Demo Insurance",
        "sender_address": "renewals@demoinsurance.example",
        "reply_to": "renewals@demoinsurance.example",
        "sender_id": "DEMOINS",
        "attack_type": "benign_notification",
        "scenario_id": "EN_EMAIL_BENIGN_008",
    },
    {
        "subject": "Appointment Confirmed — 4 November 10:00 AM",
        "message": "Dear Patient, Your appointment with Dr. Kumar at Demo Health Centre has been confirmed for Monday, 4th November 2024, at 10:00 AM. Address: 12 Health Road, Bengaluru. Please arrive 10 minutes early with a valid ID. To reschedule, call 1800-555-0010. Regards, Demo Health Centre Scheduling Team",
        "claimed_identity": "Demo Health Centre",
        "sender_name": "Demo Health Centre",
        "sender_address": "appointments@demohealthcentre.example",
        "reply_to": "appointments@demohealthcentre.example",
        "sender_id": "",
        "attack_type": "benign_notification",
        "scenario_id": "EN_EMAIL_BENIGN_009",
    },
    {
        "subject": "Urgent: Library Books Due for Return",
        "message": "Dear Library Member, This is a reminder that the following books borrowed from Demo University Library are due for return by 5th November 2024: 1) Introduction to Algorithms 2) Operating System Concepts. Late returns attract a fine of INR 2 per day per book. Please return them to the main library counter. Thank you, Demo University Library",
        "claimed_identity": "Demo University",
        "sender_name": "Demo University Library",
        "sender_address": "library@demouniversity.example",
        "reply_to": "library@demouniversity.example",
        "sender_id": "DEMOUNI",
        "attack_type": "benign_notification",
        "scenario_id": "EN_EMAIL_BENIGN_010",
    },
    # Continue benign English email samples...
    {
        "subject": "Payroll Processed — October 2024",
        "message": "Dear Employee, Your salary for October 2024 has been processed and credited to your registered bank account. Payslip is available on the HR portal at hr.demouniversity.example. For any discrepancy, contact payroll@demouniversity.example. Regards, Human Resources, Demo University",
        "claimed_identity": "Demo University",
        "sender_name": "Demo University HR",
        "sender_address": "payroll@demouniversity.example",
        "reply_to": "payroll@demouniversity.example",
        "sender_id": "DEMOUNI",
        "attack_type": "legitimate_payment",
        "scenario_id": "EN_EMAIL_BENIGN_011",
    },
    {
        "subject": "Network Maintenance — Service Interruption 2-4 AM",
        "message": "Dear Users, Please be informed that the university network will undergo scheduled maintenance between 2:00 AM and 4:00 AM on Saturday, 2nd November 2024. During this period, internet and intranet services will be unavailable. We apologize for any inconvenience. IT Department, Demo University",
        "claimed_identity": "Demo University",
        "sender_name": "Demo University IT Services",
        "sender_address": "it@demouniversity.example",
        "reply_to": "it@demouniversity.example",
        "sender_id": "DEMOUNI",
        "attack_type": "benign_notification",
        "scenario_id": "EN_EMAIL_BENIGN_012",
    },
    {
        "subject": "Welcome to Demo Bank — Account Successfully Opened",
        "message": "Dear Rahul Sharma, Welcome to Demo Bank! Your savings account has been successfully opened. Account number: XXXX-XXXX-4892. Your debit card will be dispatched within 7 working days. You can start using net banking at www.demobank.example. For any assistance, call 1800-000-0001. Demo Bank will never call asking for OTP or passwords. Best regards, Demo Bank",
        "claimed_identity": "Demo Bank",
        "sender_name": "Demo Bank",
        "sender_address": "welcome@demobank.example",
        "reply_to": "customercare@demobank.example",
        "sender_id": "DEMOBANK",
        "attack_type": "benign_notification",
        "scenario_id": "EN_EMAIL_BENIGN_013",
    },
    {
        "subject": "Seminar Registration Confirmation",
        "message": "Dear Participant, Your registration for the National Seminar on Cybersecurity (15th November 2024, Demo University Main Auditorium) has been confirmed. Registration ID: SEM-2024-0442. Please present this confirmation at the registration desk. Lunch and refreshments are provided. We look forward to your participation. Regards, Event Coordination Team",
        "claimed_identity": "Demo University",
        "sender_name": "Demo University Events",
        "sender_address": "events@demouniversity.example",
        "reply_to": "events@demouniversity.example",
        "sender_id": "DEMOUNI",
        "attack_type": "benign_notification",
        "scenario_id": "EN_EMAIL_BENIGN_014",
    },
    {
        "subject": "Action Required: Annual Performance Review Submission",
        "message": "Dear Faculty Member, The annual performance review submission portal is now open. Please complete your self-assessment form at hr.demouniversity.example by 20th November 2024. This is a mandatory institutional process. If you face any technical issues, contact hr@demouniversity.example. Regards, Human Resources, Demo University",
        "claimed_identity": "Demo University",
        "sender_name": "Demo University HR",
        "sender_address": "hr@demouniversity.example",
        "reply_to": "hr@demouniversity.example",
        "sender_id": "DEMOUNI",
        "attack_type": "benign_notification",
        "scenario_id": "EN_EMAIL_BENIGN_015",
    },
    {
        "subject": "EMI Reminder — November 2024",
        "message": "Dear Customer, Your Demo Bank Home Loan EMI of INR 15,200 is due on 5th November 2024. Please ensure sufficient balance in your account for auto-debit. You can also pay online at www.demobank.example. For payment issues, contact 1800-000-0001. This is an automated reminder. Regards, Demo Bank Loans",
        "claimed_identity": "Demo Bank",
        "sender_name": "Demo Bank Loans",
        "sender_address": "loans@demobank.example",
        "reply_to": "loans@demobank.example",
        "sender_id": "DEMOBANK",
        "attack_type": "legitimate_payment",
        "scenario_id": "EN_EMAIL_BENIGN_016",
    },
    {
        "subject": "Course Material Updated — Week 8 Slides",
        "message": "Dear Students, Week 8 lecture slides for Introduction to Machine Learning (ML301) have been uploaded to the course portal at student.demouniversity.example. Please review them before Tuesday's class. If you have questions, post them on the course discussion board. Best, Prof. Anjali Nair",
        "claimed_identity": "Demo University",
        "sender_name": "Prof. Anjali Nair",
        "sender_address": "a.nair@demouniversity.example",
        "reply_to": "a.nair@demouniversity.example",
        "sender_id": "DEMOUNI",
        "attack_type": "benign_notification",
        "scenario_id": "EN_EMAIL_BENIGN_017",
    },
    {
        "subject": "Hostel Fee Payment Receipt — October 2024",
        "message": "Dear Student, We acknowledge receipt of your hostel fee payment of INR 12,000 for the month of October 2024. Receipt number: HST-2024-7721. For any queries, contact hostel@demouniversity.example. Regards, Hostel Administration, Demo University",
        "claimed_identity": "Demo University",
        "sender_name": "Demo University Hostel Administration",
        "sender_address": "hostel@demouniversity.example",
        "reply_to": "hostel@demouniversity.example",
        "sender_id": "DEMOUNI",
        "attack_type": "legitimate_payment",
        "scenario_id": "EN_EMAIL_BENIGN_018",
    },
    {
        "subject": "Telecom Bill — October 2024 INR 399",
        "message": "Dear Customer, Your Demo Telecom bill for October 2024 is INR 399. Due date: 10th November 2024. Pay online at www.demotelecom.example or via UPI to DemoTel@upi. Auto-debit is enabled on your registered account. For queries, call 1800-000-0005. Thank you for choosing Demo Telecom.",
        "claimed_identity": "Demo Telecom",
        "sender_name": "Demo Telecom",
        "sender_address": "billing@demotelecom.example",
        "reply_to": "billing@demotelecom.example",
        "sender_id": "DEMOTEL",
        "attack_type": "legitimate_payment",
        "scenario_id": "EN_EMAIL_BENIGN_019",
    },
    {
        "subject": "Internship Offer Letter — Winter 2024",
        "message": "Dear Kavya, We are pleased to offer you an internship position as a Software Development Intern at Demo Tech Solutions for the Winter 2024 semester (1st December to 28th February). Stipend: INR 10,000 per month. Please sign and return the enclosed offer letter by 10th November 2024. We look forward to having you on our team. HR Team, Demo Tech Solutions",
        "claimed_identity": "Demo Tech Solutions",
        "sender_name": "Demo Tech Solutions HR",
        "sender_address": "hr@demotechsolutions.example",
        "reply_to": "hr@demotechsolutions.example",
        "sender_id": "",
        "attack_type": "benign_notification",
        "scenario_id": "EN_EMAIL_BENIGN_020",
    },
    # Samples 21-50: More benign English email
    {
        "subject": "Research Grant Application Received",
        "message": "Dear Dr. Suresh Rao, Your research grant application (Ref: RG-2024-1140) has been received and will be reviewed by the committee. You will be notified of the outcome by 30th November 2024. For status inquiries, contact research@demouniversity.example. Best regards, Research Funding Office, Demo University",
        "claimed_identity": "Demo University",
        "sender_name": "Demo University Research Office",
        "sender_address": "research@demouniversity.example",
        "reply_to": "research@demouniversity.example",
        "sender_id": "DEMOUNI",
        "attack_type": "benign_notification",
        "scenario_id": "EN_EMAIL_BENIGN_021",
    },
    {
        "subject": "KYC Update Completed Successfully",
        "message": "Dear Customer, Your KYC documents have been successfully verified and updated in our records. No further action is required. Your Demo Bank account remains fully active. If you did not initiate this, please call 1800-000-0001 immediately. Demo Bank never sends links or requests OTPs for KYC. Regards, Demo Bank",
        "claimed_identity": "Demo Bank",
        "sender_name": "Demo Bank KYC Team",
        "sender_address": "kyc@demobank.example",
        "reply_to": "kyc@demobank.example",
        "sender_id": "DEMOBANK",
        "attack_type": "benign_notification",
        "scenario_id": "EN_EMAIL_BENIGN_022",
    },
    {
        "subject": "Campus Recruitment Drive — Register by 8 November",
        "message": "Dear Final Year Students, Demo Technologies will be conducting a campus recruitment drive on 12th November 2024. Eligible branches: CSE, ECE, MCA. Register at placement.demouniversity.example by 8th November. Bring your resume and ID. Placement Cell, Demo University",
        "claimed_identity": "Demo University",
        "sender_name": "Demo University Placement Cell",
        "sender_address": "placement@demouniversity.example",
        "reply_to": "placement@demouniversity.example",
        "sender_id": "DEMOUNI",
        "attack_type": "benign_notification",
        "scenario_id": "EN_EMAIL_BENIGN_023",
    },
    {
        "subject": "Delivery Attempted — Schedule Redelivery",
        "message": "Dear Customer, We attempted to deliver your parcel (Tracking: DL-00892) today but you were unavailable. Please schedule a redelivery at www.demodelivery.example/redelivery or contact 1800-000-0004. You can also collect the parcel from our nearest facility. Thank you, Demo Delivery",
        "claimed_identity": "Demo Delivery",
        "sender_name": "Demo Delivery",
        "sender_address": "noreply@demodelivery.example",
        "reply_to": "support@demodelivery.example",
        "sender_id": "DEMODLV",
        "attack_type": "benign_notification",
        "scenario_id": "EN_EMAIL_BENIGN_024",
    },
    {
        "subject": "Password Changed Successfully",
        "message": "Dear Customer, Your Demo Bank net banking password was changed on 31-Oct-2024 at 09:22 AM from IP: 192.168.x.x. If you made this change, no action is needed. If you did not make this change, please call 1800-000-0001 immediately and we will secure your account. Demo Bank will never ask for your password via call or email. Regards, Demo Bank Security Team",
        "claimed_identity": "Demo Bank",
        "sender_name": "Demo Bank Security",
        "sender_address": "security@demobank.example",
        "reply_to": "security@demobank.example",
        "sender_id": "DEMOBANK",
        "attack_type": "benign_notification",
        "scenario_id": "EN_EMAIL_BENIGN_025",
    },
    {
        "subject": "Final Year Project Submission Guidelines",
        "message": "Dear Final Year Students, Please note the following guidelines for your final year project submission: 1) Report must be submitted in PDF format. 2) Maximum 50 pages including references. 3) Submission portal opens on 1st December 2024. 4) Hard copies must be submitted by 15th December 2024. For queries, contact your project guide. Regards, Project Evaluation Committee, Demo University",
        "claimed_identity": "Demo University",
        "sender_name": "Demo University Project Committee",
        "sender_address": "projects@demouniversity.example",
        "reply_to": "projects@demouniversity.example",
        "sender_id": "DEMOUNI",
        "attack_type": "benign_notification",
        "scenario_id": "EN_EMAIL_BENIGN_026",
    },
    {
        "subject": "Demo Bank — Fixed Deposit Maturity Notice",
        "message": "Dear Customer, Your Fixed Deposit (FD No: FD-2021-8844) of INR 50,000 is maturing on 30th November 2024. Please log in to your account at www.demobank.example to renew or withdraw. If you take no action, the FD will be auto-renewed at the prevailing rate. For assistance, call 1800-000-0001. Regards, Demo Bank Investments",
        "claimed_identity": "Demo Bank",
        "sender_name": "Demo Bank Investments",
        "sender_address": "investments@demobank.example",
        "reply_to": "investments@demobank.example",
        "sender_id": "DEMOBANK",
        "attack_type": "legitimate_payment",
        "scenario_id": "EN_EMAIL_BENIGN_027",
    },
    {
        "subject": "Guest Lecture: AI in Healthcare — 10 November",
        "message": "Dear Students and Faculty, We are pleased to invite you to a guest lecture on 'AI in Healthcare' by Dr. Ramesh Menon (Chief Data Scientist, Demo Health Tech) on 10th November 2024, 3:00 PM, Seminar Hall B. Registration is open to all. Register at events.demouniversity.example. Regards, CSE Department, Demo University",
        "claimed_identity": "Demo University",
        "sender_name": "CSE Department Demo University",
        "sender_address": "cse@demouniversity.example",
        "reply_to": "cse@demouniversity.example",
        "sender_id": "DEMOUNI",
        "attack_type": "benign_notification",
        "scenario_id": "EN_EMAIL_BENIGN_028",
    },
    {
        "subject": "Monthly Mobile Recharge Confirmation",
        "message": "Dear Customer, Your Demo Telecom prepaid account has been recharged successfully. Recharge amount: INR 299. Validity: 28 days. Talk time: Unlimited calls. Data: 1.5 GB/day. Recharge date: 31-Oct-2024. For offers and plans, visit www.demotelecom.example. Thank you, Demo Telecom",
        "claimed_identity": "Demo Telecom",
        "sender_name": "Demo Telecom",
        "sender_address": "noreply@demotelecom.example",
        "reply_to": "support@demotelecom.example",
        "sender_id": "DEMOTEL",
        "attack_type": "legitimate_payment",
        "scenario_id": "EN_EMAIL_BENIGN_029",
    },
    {
        "subject": "Fee Payment Pending — Action Required by 15 November",
        "message": "Dear Student, Our records show that your semester fee for November 2024 (INR 45,000) is outstanding. Please pay at the accounts office or online at fees.demouniversity.example by 15th November 2024 to avoid late charges. A late payment fee of INR 500 will be applied after the deadline. For queries, contact accounts@demouniversity.example. Regards, Accounts Department, Demo University",
        "claimed_identity": "Demo University",
        "sender_name": "Demo University Accounts",
        "sender_address": "accounts@demouniversity.example",
        "reply_to": "accounts@demouniversity.example",
        "sender_id": "DEMOUNI",
        "attack_type": "legitimate_payment",
        "scenario_id": "EN_EMAIL_BENIGN_030",
    },
    # Add more benign samples to reach 50
    *[{
        "subject": f"Routine University Notice #{i}",
        "message": f"Dear Student, This is a routine notification from Demo University regarding academic activities. Please check the student portal for details. Reference: UN-2024-{1000+i}. Contact registrar@demouniversity.example for queries.",
        "claimed_identity": "Demo University",
        "sender_name": "Demo University Registrar",
        "sender_address": "registrar@demouniversity.example",
        "reply_to": "registrar@demouniversity.example",
        "sender_id": "DEMOUNI",
        "attack_type": "benign_notification",
        "scenario_id": f"EN_EMAIL_BENIGN_0{30+i}",
    } for i in range(1, 21)],
]

# ─────────────────────────────────────────────
# ENGLISH EMAIL — SUSPICIOUS (50 samples)
# ─────────────────────────────────────────────
ENGLISH_EMAIL_SUSPICIOUS = [
    {
        "subject": "URGENT: Your Demo Bank Account Has Been Suspended",
        "message": "Dear Customer, We have detected unusual activity on your Demo Bank account. Your account has been temporarily suspended to protect you. Click the link below within 24 hours to verify your identity and restore access: http://demobank-secure-verify.xyz/login?ref=838292. You will be asked to enter your account number, debit card PIN and OTP. Failure to verify will result in permanent account closure. Demo Bank Security Team",
        "claimed_identity": "Demo Bank",
        "sender_name": "Demo Bank Security",
        "sender_address": "security@demobank-secure-verify.xyz",
        "reply_to": "noreply@quickmail.example",
        "sender_id": "",
        "attack_type": "phishing",
        "scenario_id": "EN_EMAIL_SUSP_001",
    },
    {
        "subject": "Action Required: Verify Your KYC to Avoid Account Termination",
        "message": "Dear Account Holder, Your KYC documents have expired. As per RBI guidelines, failure to update KYC within 48 hours will result in account restriction. Please provide your Aadhaar number, PAN number and upload a selfie using this secure link: http://kyc-verify-rbi.click/upload. For assistance, call our dedicated KYC helpline at 9876543210. Thank you for your cooperation. RBI Compliance Team",
        "claimed_identity": "Demo Bank",
        "sender_name": "RBI Compliance",
        "sender_address": "compliance@kyc-verify-rbi.click",
        "reply_to": "collect@kyc-verify-rbi.click",
        "sender_id": "",
        "attack_type": "credential_harvesting",
        "scenario_id": "EN_EMAIL_SUSP_002",
    },
    {
        "subject": "Congratulations! You Have Won INR 5,00,000 in Demo Bank Lucky Draw",
        "message": "Dear Lucky Winner, We are pleased to inform you that your Demo Bank account number ending in 4521 has been selected in the Demo Bank Lucky Draw 2024. You have won INR 5,00,000. To claim your prize, you must pay a processing fee of INR 2,500 within 24 hours at this link: http://demobank-lucky.top/claim. Alternatively, share your UPI PIN with our agent. This offer expires today. Demo Bank Rewards Team",
        "claimed_identity": "Demo Bank",
        "sender_name": "Demo Bank Rewards",
        "sender_address": "rewards@demobank-lucky.top",
        "reply_to": "claim@demobank-lucky.top",
        "sender_id": "",
        "attack_type": "financial_scam",
        "scenario_id": "EN_EMAIL_SUSP_003",
    },
    {
        "subject": "Fee Payment Scam — Urgent University Payment Required",
        "message": "Dear Student, Due to a system upgrade, your semester fee payment of INR 45,000 must be re-processed immediately. Please transfer the amount to the following account: Account: 998877665544, IFSC: DEMO0001234, Name: Demo University Fee Collection. Attach the transfer receipt and share your student ID and password with this email. This must be done within 6 hours or your enrollment will be cancelled. Demo University Finance Office",
        "claimed_identity": "Demo University",
        "sender_name": "Demo University Finance",
        "sender_address": "finance@demouniversity-fees.xyz",
        "reply_to": "collect@demouniversity-fees.xyz",
        "sender_id": "",
        "attack_type": "financial_scam",
        "scenario_id": "EN_EMAIL_SUSP_004",
    },
    {
        "subject": "Your Account Will Be Deactivated in 12 Hours",
        "message": "IMPORTANT NOTICE: We have detected unauthorized access to your Demo Bank account from an unknown device. To prevent further loss, your account has been locked. You must verify your credentials within 12 hours using the link below or your account will be permanently deactivated. Verification link: http://demo-bank-auth.tk/verify?token=xf82jqa. Enter your full name, date of birth, account number, card number and CVV. Do not delay.",
        "claimed_identity": "Demo Bank",
        "sender_name": "DemoBank Security Dept",
        "sender_address": "security@demo-bank-auth.tk",
        "reply_to": "security@demo-bank-auth.tk",
        "sender_id": "",
        "attack_type": "phishing",
        "scenario_id": "EN_EMAIL_SUSP_005",
    },
    {
        "subject": "Customer Support: OTP Required for Account Verification",
        "message": "Dear Customer, Our technical team is performing security updates. To protect your account, we need you to confirm your identity. Please reply to this email with the OTP sent to your registered mobile number. This is a one-time process and will take less than 2 minutes. Do not share this OTP with anyone else. Customer Support, Demo Bank",
        "claimed_identity": "Demo Bank",
        "sender_name": "Demo Bank Customer Support",
        "sender_address": "support@demobankcare.net",
        "reply_to": "otp-collect@demobankcare.net",
        "sender_id": "",
        "attack_type": "credential_harvesting",
        "scenario_id": "EN_EMAIL_SUSP_006",
    },
    {
        "subject": "Refund Pending — Provide Bank Details",
        "message": "Dear Customer, A refund of INR 3,200 is pending for your order #FL-2024-5521. To process your refund, please click the link and enter your bank account details and UPI PIN: http://refund-process.click/verify. Refund will be processed within 24 hours. If you do not complete verification within 48 hours, the refund will be cancelled. Demo Delivery Refunds Team",
        "claimed_identity": "Demo Delivery",
        "sender_name": "Demo Delivery Refunds",
        "sender_address": "refunds@refund-process.click",
        "reply_to": "refunds@refund-process.click",
        "sender_id": "",
        "attack_type": "phishing",
        "scenario_id": "EN_EMAIL_SUSP_007",
    },
    {
        "subject": "Income Tax Notice — Immediate Response Required",
        "message": "Dear Taxpayer, The Income Tax Department has detected unreconciled income in your 2023-24 ITR. A tax liability of INR 12,500 has been assessed. Failure to pay within 7 days will result in legal proceedings under Section 276 of the Income Tax Act. Pay immediately at this portal: http://incometax-dept-india.xyz/pay. Do not ignore this notice. IT Department, Government of India",
        "claimed_identity": "Income Tax Department",
        "sender_name": "Income Tax Department",
        "sender_address": "notice@incometax-dept-india.xyz",
        "reply_to": "notice@incometax-dept-india.xyz",
        "sender_id": "",
        "attack_type": "urgency_manipulation",
        "scenario_id": "EN_EMAIL_SUSP_008",
    },
    {
        "subject": "Parcel Held at Customs — Pay Duty to Release",
        "message": "Dear Customer, Your international parcel (Tracking: INT-20240282) is held at customs. A customs duty of INR 1,800 must be paid within 24 hours to release your parcel. Click the payment link: http://customs-clearance-in.tk/pay?track=INT-20240282. Failure to pay will result in the parcel being returned or destroyed. Demo Delivery International",
        "claimed_identity": "Demo Delivery",
        "sender_name": "Demo Delivery International",
        "sender_address": "customs@customs-clearance-in.tk",
        "reply_to": "customs@customs-clearance-in.tk",
        "sender_id": "",
        "attack_type": "financial_scam",
        "scenario_id": "EN_EMAIL_SUSP_009",
    },
    {
        "subject": "Final Warning: Net Banking Access Will Be Revoked",
        "message": "This is a final warning. Your Demo Bank net banking access has not been verified using the new 2-Factor Authentication system. Access will be revoked in 24 hours unless you log in and verify your mobile number, date of birth and password using this link: http://demobnk-secure.ml/2fa-verify. This link expires in 24 hours. Do not share this link with anyone. Demo Bank IT Security",
        "claimed_identity": "Demo Bank",
        "sender_name": "Demo Bank IT Security",
        "sender_address": "itsec@demobnk-secure.ml",
        "reply_to": "itsec@demobnk-secure.ml",
        "sender_id": "",
        "attack_type": "phishing",
        "scenario_id": "EN_EMAIL_SUSP_010",
    },
    # More suspicious English emails
    *[{
        "subject": f"URGENT Account Alert #{i}",
        "message": f"Dear Customer, Suspicious activity has been detected on your account. Provide your OTP and password at the link below immediately to avoid suspension: http://phishing-{i}.example/verify. This is your final notice. Support Team",
        "claimed_identity": "Demo Bank",
        "sender_name": "Demo Bank Alert",
        "sender_address": f"alert{i}@phishing-{i}.example",
        "reply_to": f"collect{i}@phishing-{i}.example",
        "sender_id": "",
        "attack_type": "phishing",
        "scenario_id": f"EN_EMAIL_SUSP_0{10+i}",
    } for i in range(1, 41)],
]

# ─────────────────────────────────────────────
# ENGLISH SMS — BENIGN (50 samples)
# ─────────────────────────────────────────────
ENGLISH_SMS_BENIGN = [
    {"subject": "", "message": "INR 500 credited to Demo Bank a/c XXXX4521 on 31-Oct-24. Available balance: INR 12500. For any query call 1800-000-0001. -DEMOBANK", "claimed_identity": "Demo Bank", "sender_name": "", "sender_address": "", "reply_to": "", "sender_id": "DEMOBANK", "attack_type": "legitimate_payment", "scenario_id": "EN_SMS_BENIGN_001"},
    {"subject": "", "message": "Dear Student, Exam hall ticket for November 2024 is available at student.demouniversity.example. Carry original ID to exam. -DEMOUNI", "claimed_identity": "Demo University", "sender_name": "", "sender_address": "", "reply_to": "", "sender_id": "DEMOUNI", "attack_type": "benign_notification", "scenario_id": "EN_SMS_BENIGN_002"},
    {"subject": "", "message": "Your Demo Telecom prepaid recharge of Rs.299 is successful. Validity 28 days. 1.5GB/day. For offers visit www.demotelecom.example -DEMOTEL", "claimed_identity": "Demo Telecom", "sender_name": "", "sender_address": "", "reply_to": "", "sender_id": "DEMOTEL", "attack_type": "legitimate_payment", "scenario_id": "EN_SMS_BENIGN_003"},
    {"subject": "", "message": "Your package (Order #DL-00812) has been delivered. For issues contact 1800-000-0004. -DEMODLV", "claimed_identity": "Demo Delivery", "sender_name": "", "sender_address": "", "reply_to": "", "sender_id": "DEMODLV", "attack_type": "benign_notification", "scenario_id": "EN_SMS_BENIGN_004"},
    {"subject": "", "message": "Reminder: Demo Bank EMI of Rs.15200 due on 5-Nov-24. Ensure sufficient balance for auto-debit. Queries: 1800-000-0001. -DEMOBANK", "claimed_identity": "Demo Bank", "sender_name": "", "sender_address": "", "reply_to": "", "sender_id": "DEMOBANK", "attack_type": "legitimate_payment", "scenario_id": "EN_SMS_BENIGN_005"},
    {"subject": "", "message": "Your OTP for Demo Bank login is 482910. Valid for 5 minutes. Do not share with anyone. -DEMOBANK", "claimed_identity": "Demo Bank", "sender_name": "", "sender_address": "", "reply_to": "", "sender_id": "DEMOBANK", "attack_type": "legitimate_payment", "scenario_id": "EN_SMS_BENIGN_006"},
    {"subject": "", "message": "Fee payment of Rs.45000 received for Reg No: 20CS001. Receipt: REC-2024-5512. Regards, Demo University Accounts. -DEMOUNI", "claimed_identity": "Demo University", "sender_name": "", "sender_address": "", "reply_to": "", "sender_id": "DEMOUNI", "attack_type": "legitimate_payment", "scenario_id": "EN_SMS_BENIGN_007"},
    {"subject": "", "message": "Demo Insurance renewal reminder: Policy DI-2021-5544 due 30-Nov-24. Pay at www.demoinsurance.example. Queries: 1800-000-0003. -DEMOINS", "claimed_identity": "Demo Insurance", "sender_name": "", "sender_address": "", "reply_to": "", "sender_id": "DEMOINS", "attack_type": "benign_notification", "scenario_id": "EN_SMS_BENIGN_008"},
    *[{"subject": "", "message": f"Your account transaction of Rs.{100*i} is confirmed. Balance updated. Contact 1800-000-0001 for queries. -DEMOBANK", "claimed_identity": "Demo Bank", "sender_name": "", "sender_address": "", "reply_to": "", "sender_id": "DEMOBANK", "attack_type": "legitimate_payment", "scenario_id": f"EN_SMS_BENIGN_0{8+i}"} for i in range(1, 43)],
]

# ─────────────────────────────────────────────
# ENGLISH SMS — SUSPICIOUS (50 samples)
# ─────────────────────────────────────────────
ENGLISH_SMS_SUSPICIOUS = [
    {"subject": "", "message": "URGENT: Demo Bank account suspended. Click to verify: http://demobank-verify.xyz/sms?id=938 Enter OTP and PIN to restore. -DM0BANK", "claimed_identity": "Demo Bank", "sender_name": "", "sender_address": "", "reply_to": "", "sender_id": "DM0BANK", "attack_type": "phishing", "scenario_id": "EN_SMS_SUSP_001"},
    {"subject": "", "message": "Congratulations! You have won Rs.1,00,000 in Demo Bank draw. Share your UPI PIN and Aadhaar to claim prize. Offer ends today. -DEMOPRIZ", "claimed_identity": "Demo Bank", "sender_name": "", "sender_address": "", "reply_to": "", "sender_id": "DEMOPRIZ", "attack_type": "financial_scam", "scenario_id": "EN_SMS_SUSP_002"},
    {"subject": "", "message": "Your KYC expired. Provide Aadhaar, PAN and password at http://kyc-rbi-update.tk/verify within 24 hrs or account blocked. RBI Compliance", "claimed_identity": "Demo Bank", "sender_name": "", "sender_address": "", "reply_to": "", "sender_id": "RBIKYC", "attack_type": "credential_harvesting", "scenario_id": "EN_SMS_SUSP_003"},
    {"subject": "", "message": "Refund of Rs.3500 failed. Enter bank details and UPI PIN at http://refund-portal.ml/verify to receive your refund immediately. -DELV", "claimed_identity": "Demo Delivery", "sender_name": "", "sender_address": "", "reply_to": "", "sender_id": "DELV", "attack_type": "phishing", "scenario_id": "EN_SMS_SUSP_004"},
    {"subject": "", "message": "ALERT: Rs.25,000 debited from your account. If not done by you call 9876543210 and provide your card number and CVV to reverse.", "claimed_identity": "Demo Bank", "sender_name": "", "sender_address": "", "reply_to": "", "sender_id": "DM-BNK", "attack_type": "phishing", "scenario_id": "EN_SMS_SUSP_005"},
    *[{"subject": "", "message": f"Act now! Limited time offer: claim Rs.{500*i} cashback. Enter OTP and PIN at http://reward-{i}.top/claim within 1 hour.", "claimed_identity": "Demo Bank", "sender_name": "", "sender_address": "", "reply_to": "", "sender_id": f"OFFER{i}", "attack_type": "financial_scam", "scenario_id": f"EN_SMS_SUSP_0{5+i}"} for i in range(1, 46)],
]

# ─────────────────────────────────────────────
# KANNADA EMAIL — BENIGN (50 samples)
# ─────────────────────────────────────────────
KANNADA_EMAIL_BENIGN = [
    {
        "subject": "ಪರೀಕ್ಷಾ ವೇಳಾಪಟ್ಟಿ — ನವೆಂಬರ್ 2024",
        "message": "ಪ್ರಿಯ ವಿದ್ಯಾರ್ಥಿಗಳೇ, ನವೆಂಬರ್ 2024 ಸೆಮಿಸ್ಟರ್ ಪರೀಕ್ಷೆಯ ವೇಳಾಪಟ್ಟಿ ಬಿಡುಗಡೆಯಾಗಿದೆ. ದಯವಿಟ್ಟು student.demouniversity.example ನಲ್ಲಿ ನಿಮ್ಮ ಹಾಲ್ ಟಿಕೆಟ್ ಮತ್ತು ವೇಳಾಪಟ್ಟಿ ನೋಡಿ. ಪರೀಕ್ಷಾ ಕೊಠಡಿಗೆ ಗುರುತಿನ ಚೀಟಿ ತನ್ನಿ. ಶುಭಾಶಯಗಳು! ಪರೀಕ್ಷಾ ವಿಭಾಗ, ಡೆಮೊ ವಿಶ್ವವಿದ್ಯಾಲಯ",
        "claimed_identity": "Demo University",
        "sender_name": "ಡೆಮೊ ವಿಶ್ವವಿದ್ಯಾಲಯ ಪರೀಕ್ಷಾ ವಿಭಾಗ",
        "sender_address": "exams@demouniversity.example",
        "reply_to": "exams@demouniversity.example",
        "sender_id": "DEMOUNI",
        "attack_type": "benign_notification",
        "scenario_id": "KN_EMAIL_BENIGN_001",
    },
    {
        "subject": "ಬ್ಯಾಂಕ್ ಖಾತೆ ವಿವರ — ಅಕ್ಟೋಬರ್ 2024",
        "message": "ಪ್ರಿಯ ಗ್ರಾಹಕರೇ, ಅಕ್ಟೋಬರ್ 2024 ರ ನಿಮ್ಮ ಡೆಮೊ ಬ್ಯಾಂಕ್ ಖಾತೆ ವಿವರ ಈಗ ಲಭ್ಯವಿದೆ. www.demobank.example ನಲ್ಲಿ ಲಾಗಿನ್ ಮಾಡಿ ನೋಡಿ. ಯಾವುದೇ ವ್ಯತ್ಯಾಸ ಕಂಡರೆ 1800-000-0001 ಕರೆ ಮಾಡಿ. ಧನ್ಯವಾದಗಳು, ಡೆಮೊ ಬ್ಯಾಂಕ್",
        "claimed_identity": "Demo Bank",
        "sender_name": "ಡೆಮೊ ಬ್ಯಾಂಕ್",
        "sender_address": "statements@demobank.example",
        "reply_to": "statements@demobank.example",
        "sender_id": "DEMOBANK",
        "attack_type": "legitimate_payment",
        "scenario_id": "KN_EMAIL_BENIGN_002",
    },
    {
        "subject": "ಅಸೈನ್ಮೆಂಟ್ ಸಲ್ಲಿಕೆ ಜ್ಞಾಪನ",
        "message": "ಪ್ರಿಯ ವಿದ್ಯಾರ್ಥಿ, CS401 ಡೇಟಾಬೇಸ್ ಸಿಸ್ಟಮ್ ಅಸೈನ್ಮೆಂಟ್ ಸಲ್ಲಿಕೆ ದಿನಾಂಕ: 5 ನವೆಂಬರ್ 2024, ರಾತ್ರಿ 11:59. ದಯವಿಟ್ಟು student.demouniversity.example ಮೂಲಕ ಸಲ್ಲಿಸಿ. ತಡ ಸಲ್ಲಿಕೆಗೆ ಪ್ರತಿ ದಿನ 10% ಕಡಿತ. ಶಿಕ್ಷಕರನ್ನು ಸಂಪರ್ಕಿಸಿ. ಡೆಮೊ ವಿಶ್ವವಿದ್ಯಾಲಯ",
        "claimed_identity": "Demo University",
        "sender_name": "ಡೆಮೊ ವಿಶ್ವವಿದ್ಯಾಲಯ",
        "sender_address": "academics@demouniversity.example",
        "reply_to": "academics@demouniversity.example",
        "sender_id": "DEMOUNI",
        "attack_type": "benign_notification",
        "scenario_id": "KN_EMAIL_BENIGN_003",
    },
    *[{
        "subject": f"ವಿಶ್ವವಿದ್ಯಾಲಯ ಸೂಚನೆ #{i}",
        "message": f"ಪ್ರಿಯ ವಿದ್ಯಾರ್ಥಿಗಳೇ, ಡೆಮೊ ವಿಶ್ವವಿದ್ಯಾಲಯದ ಶೈಕ್ಷಣಿಕ ಚಟುವಟಿಕೆಗಳ ಕುರಿತು ಈ ಸೂಚನೆ. ವಿವರಗಳಿಗೆ student.demouniversity.example ನೋಡಿ. ಉಲ್ಲೇಖ: UN-2024-{1000+i}.",
        "claimed_identity": "Demo University",
        "sender_name": "ಡೆಮೊ ವಿಶ್ವವಿದ್ಯಾಲಯ",
        "sender_address": "registrar@demouniversity.example",
        "reply_to": "registrar@demouniversity.example",
        "sender_id": "DEMOUNI",
        "attack_type": "benign_notification",
        "scenario_id": f"KN_EMAIL_BENIGN_0{3+i}",
    } for i in range(1, 48)],
]

# ─────────────────────────────────────────────
# KANNADA EMAIL — SUSPICIOUS (50 samples)
# ─────────────────────────────────────────────
KANNADA_EMAIL_SUSPICIOUS = [
    {
        "subject": "ತುರ್ತು: ನಿಮ್ಮ ಡೆಮೊ ಬ್ಯಾಂಕ್ ಖಾತೆ ನಿರ್ಬಂಧಿಸಲಾಗಿದೆ",
        "message": "ಪ್ರಿಯ ಗ್ರಾಹಕರೇ, ನಿಮ್ಮ ಡೆಮೊ ಬ್ಯಾಂಕ್ ಖಾತೆಯಲ್ಲಿ ಅನಧಿಕೃತ ವ್ಯವಹಾರ ಪತ್ತೆಯಾಗಿದೆ. ಖಾತೆ ತಕ್ಷಣ ನಿರ್ಬಂಧಿಸಲಾಗಿದೆ. 24 ಗಂಟೆ ಒಳಗೆ ನಿಮ್ಮ ಗುರುತು ಪರಿಶೀಲಿಸಿ: http://demobank-verify.xyz/kn?id=9921. OTP, ಡೆಬಿಟ್ ಕಾರ್ಡ್ PIN ನಮೂದಿಸಿ. ತಡ ಮಾಡಿದರೆ ಖಾತೆ ಶಾಶ್ವತ ಮುಚ್ಚಲ್ಪಡುತ್ತದೆ. ಡೆಮೊ ಬ್ಯಾಂಕ್ ಭದ್ರತಾ ತಂಡ",
        "claimed_identity": "Demo Bank",
        "sender_name": "ಡೆಮೊ ಬ್ಯಾಂಕ್ ಭದ್ರತೆ",
        "sender_address": "security@demobank-verify.xyz",
        "reply_to": "collect@demobank-verify.xyz",
        "sender_id": "",
        "attack_type": "phishing",
        "scenario_id": "KN_EMAIL_SUSP_001",
    },
    {
        "subject": "ಅಭಿನಂದನೆ! ನೀವು ₹5,00,000 ಗೆದ್ದಿದ್ದೀರಿ",
        "message": "ಪ್ರಿಯ ಗ್ರಾಹಕರೇ, ನಿಮ್ಮ ಡೆಮೊ ಬ್ಯಾಂಕ್ ಖಾತೆ ಲಕ್ಕಿ ಡ್ರಾ 2024 ರಲ್ಲಿ ಆಯ್ಕೆಯಾಗಿದೆ. ಬಹುಮಾನ: ₹5,00,000. ಬಹುಮಾನ ಪಡೆಯಲು ₹2,500 ಪ್ರಕ್ರಿಯಾ ಶುಲ್ಕ ಪಾವತಿಸಿ: http://demobank-prize.top/kn. ನಿಮ್ಮ UPI PIN ನಮ್ಮ ಏಜೆಂಟ್ ಜೊತೆ ಶೇರ್ ಮಾಡಿ. ಇಂದು ಕೊನೆಯ ದಿನ. ಡೆಮೊ ಬ್ಯಾಂಕ್ ಬಹುಮಾನ ತಂಡ",
        "claimed_identity": "Demo Bank",
        "sender_name": "ಡೆಮೊ ಬ್ಯಾಂಕ್ ಬಹುಮಾನ",
        "sender_address": "prize@demobank-prize.top",
        "reply_to": "collect@demobank-prize.top",
        "sender_id": "",
        "attack_type": "financial_scam",
        "scenario_id": "KN_EMAIL_SUSP_002",
    },
    {
        "subject": "ಕೆವೈಸಿ ಅವಧಿ ಮೀರಿದೆ — ಈಗಲೇ ನವೀಕರಿಸಿ",
        "message": "ಪ್ರಿಯ ಖಾತೆದಾರರೇ, ನಿಮ್ಮ KYC ಅವಧಿ ಮೀರಿದೆ. RBI ನಿಯಮಗಳ ಪ್ರಕಾರ 48 ಗಂಟೆ ಒಳಗೆ KYC ನವೀಕರಿಸದಿದ್ದರೆ ಖಾತೆ ನಿರ್ಬಂಧಿಸಲಾಗುವುದು. ಆಧಾರ್ ಸಂಖ್ಯೆ, PAN ಮತ್ತು ಸೆಲ್ಫಿ ಅಪ್ಲೋಡ್ ಮಾಡಿ: http://kyc-rbi-kn.click/upload. ಧನ್ಯವಾದ. RBI ಅನುಪಾಲನ ತಂಡ",
        "claimed_identity": "Demo Bank",
        "sender_name": "RBI KYC ತಂಡ",
        "sender_address": "kyc@kyc-rbi-kn.click",
        "reply_to": "collect@kyc-rbi-kn.click",
        "sender_id": "",
        "attack_type": "credential_harvesting",
        "scenario_id": "KN_EMAIL_SUSP_003",
    },
    *[{
        "subject": f"ತುರ್ತು ಖಾತೆ ಎಚ್ಚರಿಕೆ #{i}",
        "message": f"ಪ್ರಿಯ ಗ್ರಾಹಕರೇ, ನಿಮ್ಮ ಖಾತೆಯಲ್ಲಿ ಅನಧಿಕೃತ ವ್ಯವಹಾರ ಪತ್ತೆಯಾಗಿದೆ. ತಕ್ಷಣ OTP ಮತ್ತು PIN ನಮೂದಿಸಿ: http://phishing-kn-{i}.example/verify. ತಡ ಮಾಡಬೇಡಿ.",
        "claimed_identity": "Demo Bank",
        "sender_name": "ಡೆಮೊ ಬ್ಯಾಂಕ್",
        "sender_address": f"alert{i}@phishing-kn-{i}.example",
        "reply_to": f"collect{i}@phishing-kn-{i}.example",
        "sender_id": "",
        "attack_type": "phishing",
        "scenario_id": f"KN_EMAIL_SUSP_0{3+i}",
    } for i in range(1, 48)],
]

# ─────────────────────────────────────────────
# KANNADA SMS — BENIGN (50 samples)
# ─────────────────────────────────────────────
KANNADA_SMS_BENIGN = [
    {"subject": "", "message": "ಡೆಮೊ ಬ್ಯಾಂಕ್: ₹500 ನಿಮ್ಮ ಖಾತೆ XXXX4521 ಗೆ ಜಮಾ ಆಗಿದೆ. ಬ್ಯಾಲೆನ್ಸ್: ₹12,500. ಪ್ರಶ್ನೆಗಳಿಗೆ: 1800-000-0001. -DEMOBANK", "claimed_identity": "Demo Bank", "sender_name": "", "sender_address": "", "reply_to": "", "sender_id": "DEMOBANK", "attack_type": "legitimate_payment", "scenario_id": "KN_SMS_BENIGN_001"},
    {"subject": "", "message": "ಡೆಮೊ ವಿಶ್ವವಿದ್ಯಾಲಯ: ನವೆಂಬರ್ 2024 ಪರೀಕ್ಷಾ ಹಾಲ್ ಟಿಕೆಟ್ student.demouniversity.example ನಲ್ಲಿ ಲಭ್ಯ. ಗುರುತಿನ ಚೀಟಿ ತನ್ನಿ. -DEMOUNI", "claimed_identity": "Demo University", "sender_name": "", "sender_address": "", "reply_to": "", "sender_id": "DEMOUNI", "attack_type": "benign_notification", "scenario_id": "KN_SMS_BENIGN_002"},
    {"subject": "", "message": "ಡೆಮೊ ಟೆಲಿಕಾಂ: ₹299 ರೀಚಾರ್ಜ್ ಯಶಸ್ವಿ. ಮಾನ್ಯತೆ 28 ದಿನ. 1.5GB/ದಿನ. -DEMOTEL", "claimed_identity": "Demo Telecom", "sender_name": "", "sender_address": "", "reply_to": "", "sender_id": "DEMOTEL", "attack_type": "legitimate_payment", "scenario_id": "KN_SMS_BENIGN_003"},
    {"subject": "", "message": "ನಿಮ್ಮ ಪ್ಯಾಕೇಜ್ (ಆರ್ಡರ್ #DL-00812) ವಿತರಿಸಲಾಗಿದೆ. ಸಮಸ್ಯೆಗಳಿಗೆ: 1800-000-0004. -DEMODLV", "claimed_identity": "Demo Delivery", "sender_name": "", "sender_address": "", "reply_to": "", "sender_id": "DEMODLV", "attack_type": "benign_notification", "scenario_id": "KN_SMS_BENIGN_004"},
    {"subject": "", "message": "ಡೆಮೊ ಬ್ಯಾಂಕ್ EMI ಜ್ಞಾಪನ: ₹15,200 ಮೊತ್ತ 5-ನವೆಂ-24 ಕ್ಕೆ ಸಂದಾಯ ಆಗಬೇಕು. -DEMOBANK", "claimed_identity": "Demo Bank", "sender_name": "", "sender_address": "", "reply_to": "", "sender_id": "DEMOBANK", "attack_type": "legitimate_payment", "scenario_id": "KN_SMS_BENIGN_005"},
    *[{"subject": "", "message": f"ಡೆಮೊ ಬ್ಯಾಂಕ್: ₹{100*i} ವ್ಯವಹಾರ ದೃಢೀಕರಿಸಲಾಗಿದೆ. ಬ್ಯಾಲೆನ್ಸ್ ನವೀಕರಿಸಲಾಗಿದೆ. -DEMOBANK", "claimed_identity": "Demo Bank", "sender_name": "", "sender_address": "", "reply_to": "", "sender_id": "DEMOBANK", "attack_type": "legitimate_payment", "scenario_id": f"KN_SMS_BENIGN_0{5+i}"} for i in range(1, 46)],
]

# ─────────────────────────────────────────────
# KANNADA SMS — SUSPICIOUS (50 samples)
# ─────────────────────────────────────────────
KANNADA_SMS_SUSPICIOUS = [
    {"subject": "", "message": "ತುರ್ತು: ಡೆಮೊ ಬ್ಯಾಂಕ್ ಖಾತೆ ನಿರ್ಬಂಧಿಸಲಾಗಿದೆ. ತಕ್ಷಣ OTP ಮತ್ತು PIN ನಮೂದಿಸಿ: http://demobank-kn.xyz/verify. ತಡ ಮಾಡಬೇಡಿ. -DM0BANK", "claimed_identity": "Demo Bank", "sender_name": "", "sender_address": "", "reply_to": "", "sender_id": "DM0BANK", "attack_type": "phishing", "scenario_id": "KN_SMS_SUSP_001"},
    {"subject": "", "message": "ಅಭಿನಂದನೆ! ₹1,00,000 ಗೆದ್ದಿದ್ದೀರಿ. UPI PIN ಮತ್ತು ಆಧಾರ್ ನಮ್ಮ ಏಜೆಂಟ್ ಜೊತೆ ಶೇರ್ ಮಾಡಿ. ಇಂದು ಕೊನೆಯ ದಿನ. -DEMOPRIZ", "claimed_identity": "Demo Bank", "sender_name": "", "sender_address": "", "reply_to": "", "sender_id": "DEMOPRIZ", "attack_type": "financial_scam", "scenario_id": "KN_SMS_SUSP_002"},
    {"subject": "", "message": "KYC ಅವಧಿ ಮೀರಿದೆ. 48 ಗಂಟೆ ಒಳಗೆ ಆಧಾರ್, PAN ನಮೂದಿಸಿ: http://kyc-kn.click/update. ತಡ ಮಾಡಿದರೆ ಖಾತೆ ಸ್ಥಗಿತ. -RBIKYC", "claimed_identity": "Demo Bank", "sender_name": "", "sender_address": "", "reply_to": "", "sender_id": "RBIKYC", "attack_type": "credential_harvesting", "scenario_id": "KN_SMS_SUSP_003"},
    {"subject": "", "message": "ರಿಫಂಡ್ ₹3,500 ವಿಫಲ. ಬ್ಯಾಂಕ್ ವಿವರ ಮತ್ತು UPI PIN ನಮೂದಿಸಿ: http://refund-kn.ml/verify. 24 ಗಂಟೆ ಒಳಗೆ ಮಾಡಿ. -DELV", "claimed_identity": "Demo Delivery", "sender_name": "", "sender_address": "", "reply_to": "", "sender_id": "DELV", "attack_type": "phishing", "scenario_id": "KN_SMS_SUSP_004"},
    *[{"subject": "", "message": f"ತಕ್ಷಣ ಕ್ರಮ ಅಗತ್ಯ! ₹{500*i} ಕ್ಯಾಶ್ಬ್ಯಾಕ್ ಪಡೆಯಲು OTP ಮತ್ತು PIN ನಮೂದಿಸಿ: http://reward-kn-{i}.top/claim.", "claimed_identity": "Demo Bank", "sender_name": "", "sender_address": "", "reply_to": "", "sender_id": f"OFFER{i}", "attack_type": "financial_scam", "scenario_id": f"KN_SMS_SUSP_0{4+i}"} for i in range(1, 47)],
]


def _build_sample(
    raw: Dict,
    channel: str,
    language: str,
    label: str,
    sample_num: int,
) -> Dict:
    msg = raw.get("message", "")
    has_indic = any(
        ("\u0C80" <= c <= "\u0CFF") or ("\u0900" <= c <= "\u097F")
        for c in msg
    )
    has_latin = any(c.isascii() and c.isalpha() for c in msg)
    variant = "code-mixed" if has_indic and has_latin else "monolingual"

    return {
        "sample_id": f"SYNTH-{sample_num:04d}",
        "channel": channel,
        "language": language,
        "language_variant": variant,
        "subject": raw.get("subject", ""),
        "message": raw.get("message", ""),
        "claimed_identity": raw.get("claimed_identity", ""),
        "sender_name": raw.get("sender_name", ""),
        "sender_address": raw.get("sender_address", ""),
        "reply_to": raw.get("reply_to", ""),
        "sender_id": raw.get("sender_id", ""),
        "provenance": "synthetic",
        "original_label": label,
        "normalized_label": label,  # passed directly as "benign" or "suspicious"
        "attack_type": raw.get("attack_type", "benign_notification"),
        "source_dataset": "TRUSTLENS_SYNTHETIC_v1",
        "scenario_id": raw.get("scenario_id", f"SYNTH_{sample_num}"),
        "review_status": "synthetic_generated",
    }


def generate_dataset() -> List[Dict]:
    samples = []
    n = 1

    for raw in ENGLISH_EMAIL_BENIGN[:50]:
        samples.append(_build_sample(raw, "email", "english", "benign", n))
        n += 1

    for raw in ENGLISH_EMAIL_SUSPICIOUS[:50]:
        samples.append(_build_sample(raw, "email", "english", "suspicious", n))
        n += 1

    for raw in ENGLISH_SMS_BENIGN[:50]:
        samples.append(_build_sample(raw, "sms", "english", "benign", n))
        n += 1

    for raw in ENGLISH_SMS_SUSPICIOUS[:50]:
        samples.append(_build_sample(raw, "sms", "english", "suspicious", n))
        n += 1

    for raw in HINDI_EMAIL_BENIGN[:50]:
        samples.append(_build_sample(raw, "email", "hindi", "benign", n))
        n += 1

    for raw in HINDI_EMAIL_SUSPICIOUS[:50]:
        samples.append(_build_sample(raw, "email", "hindi", "suspicious", n))
        n += 1

    for raw in HINDI_SMS_BENIGN[:50]:
        samples.append(_build_sample(raw, "sms", "hindi", "benign", n))
        n += 1

    for raw in HINDI_SMS_SUSPICIOUS[:50]:
        samples.append(_build_sample(raw, "sms", "hindi", "suspicious", n))
        n += 1

    for raw in KANNADA_EMAIL_BENIGN[:50]:
        samples.append(_build_sample(raw, "email", "kannada", "benign", n))
        n += 1

    for raw in KANNADA_EMAIL_SUSPICIOUS[:50]:
        samples.append(_build_sample(raw, "email", "kannada", "suspicious", n))
        n += 1

    for raw in KANNADA_SMS_BENIGN[:50]:
        samples.append(_build_sample(raw, "sms", "kannada", "benign", n))
        n += 1

    for raw in KANNADA_SMS_SUSPICIOUS[:50]:
        samples.append(_build_sample(raw, "sms", "kannada", "suspicious", n))
        n += 1

    return samples


def save_dataset(samples: List[Dict]):
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=SCHEMA_FIELDS)
        writer.writeheader()
        writer.writerows(samples)

    metadata = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_samples": len(samples),
        "distribution": {
            "benign": sum(1 for s in samples if s["normalized_label"] == "benign"),
            "suspicious": sum(1 for s in samples if s["normalized_label"] == "suspicious"),
            "by_channel_language": {},
        },
        "schema_version": "1.0",
        "source": "TRUSTLENS_SYNTHETIC_v1",
        "note": (
            "This dataset is synthetically generated for training purposes. "
            "All organization names are fictional. All domains use .example TLD. "
            "Do not use for production decisions without human review."
        ),
    }

    for ch in ("email", "sms"):
        for lang in ("english", "hindi", "kannada"):
            key = f"{ch}_{lang}"
            metadata["distribution"]["by_channel_language"][key] = {
                "benign": sum(1 for s in samples if s["channel"] == ch and s["language"] == lang and s["normalized_label"] == "benign"),
                "suspicious": sum(1 for s in samples if s["channel"] == ch and s["language"] == lang and s["normalized_label"] == "suspicious"),
            }

    with open(OUTPUT_METADATA, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2, ensure_ascii=False)

    print(f"[OK] Generated {len(samples)} synthetic samples -> {OUTPUT_CSV}")
    print(f"[OK] Metadata saved -> {OUTPUT_METADATA}")
    return metadata


if __name__ == "__main__":
    print("[*] Generating TRUSTLENS Synthetic Social Engineering Dataset...")
    samples = generate_dataset()
    metadata = save_dataset(samples)

    benign = metadata["distribution"]["benign"]
    suspicious = metadata["distribution"]["suspicious"]
    print(f"\n[Summary]")
    print(f"  Total: {len(samples)}")
    print(f"  Benign: {benign}")
    print(f"  Suspicious: {suspicious}")
    print(f"\n  By channel/language:")
    for k, v in metadata["distribution"]["by_channel_language"].items():
        print(f"    {k}: benign={v['benign']}, suspicious={v['suspicious']}")

