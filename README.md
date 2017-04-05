# Secure payments using SMS

# Description
SMS are still one of the most widely available messaging services. Given this, the goal is to develop
an application for a smartphone (e.g., Android or simulated by a small program in Windows or
Linux sending and receiving SMS-like messages via a UDP channel) that enables the exchange of
SMSs in order to authorize bank transactions.
For this transaction the user must send the IBAN (2 characters and 23 digits) of the account where
the money should be transferred to, the amount of money to be transferred (8 digits).
Mechanisms must be added in order to assure a secure order (i.e., taking into account security
requirements such as integrity, confidentiality and authentication) considering SMS messaging
constraints (with a maximum of 120 characters). Techniques such as cipher text stealing can be
used to ensure that the message limits are respected. Consider the possibility of assuring
non-repudiation.