# Security review process guide

## Questions to project
1. What is the clear scope (`.sol` files) of the security review?
2. Does the project have well written specifications & code documentation?
3. What is the code coverage percentage?
4. Are there any protocols that are similar to yours, which are they?
5. What is your intended budget for this review?

Based on the answers we can discuss the effort needed, the payment amount and timing.

### Other questions to project:
1. What is your preferred channel of communication (Discord, Twitter, Telegram)?
2. Are you okay with me publishing the security review report after you apply fixes?
3. Are you okay with me being transparent with my work, findings and pay?

## Security review result & fixes review
After the time agreed upon has passed, the project will receive the security review report. The project has 7 days to apply fixes on issues found. Each issues should be fixed in a separate commit that has a message pointing to the issue being fixed. Then, a single iteration of a "fixes review" will be executed by me, free of additional charges, to verify your fixes are correct and secure. 

### Important notes for the fixes review
- for any questions or clarifications on the vulnerabilities/recommendations in the report, you can reach out to me on the intended channel of communication
- changes to be reviewed should not include anything else other than fixes for the reported issues, so no big refactorings, new features or architectural changes
- in the case that fixes are too difficult to implement or more than one iteration of reviews is needed then this is a special case that can be discussed independently of this review

## Disclaimer
A smart contract security review can never verify the complete absence of vulnerabilities. This is a time, resource and expertise bound effort where I try to find as many vulnerabilities as possible. I can not guarantee 100% security after the review or if even the review will find any problems with your smart contracts.