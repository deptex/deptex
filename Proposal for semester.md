From our talks last semester with to people that would join our calls as well as the research I've done in between the semesters I've found that **alert fatigue** is a major issue in the world of open source vulnerabilities. 



So I've done quite a bit of research using google gemini's deep research and asked it about our features last semester and what features I could be adding moving forwards, so instead of continuing to dive deeper into just the packages security and providing more alerts for like suspicious commits and such, I think that I should change it slightly. 



First thing to change: I want to add organizations and teams as 2 additional layers on top of projects and allow projects to track multiple repos (like frontend and backend are the same project). In the org and team level there will be roles and permissions which are customizable so that for example an intern cannot go creating projects and deleting projects.



Second thing to change: I have done some research into deployment and I want to change things slightly, last semester we had everything hosted on render for backend and an azure vm for the graph and sbom, but what I want to do is use Fly.io (fork off vms like they are processes) for seamless scaling so that the software can handle bursts of compute while someone is importing a repo or creating a project then scale back to zero.



Third thing to change: I want to build off of what we had last semester with the projects, I want to add a reachability analysis for the vulnerabilities, I'm not sure how hard this will be but this will help to work on the alert fatigue that companies and developers have. 



Fourth thing to change: instead of for every package tracking what's happening with their commits and doing a high level of tracking (using up a lot of compute), given the fact that orgs have tons of packages, I want to create a section in the org for "Watchtower" where I have calculated a dependency score for how dependant your org is on certain packages (10+ projects rely heavily on this) then that org can add that package to the watchtower and set up alerts for that so that we still use the work from last semesters with the commit analysis and stuff but only for the packages that orgs want.



Fifth thing to change: This idea is not fully formed but I want to try to build a layer of AI on top of many of the sections, called Aegis it would be like an ai security engineer for your org, using the claude cli or api or whatever it may be you can prompt it apply the patch for this vulnerability in all my projects -> it will spin up a vm and do that -> check for linter errors and if your unit tests still pass -> create pr on GitHub. This would be interesting depending on how much I can do with this and how far along I can get for the paper "Can you reduce vulnerability alert fatigue for developers using AI remediation". 





At the end of the semester hopefully I can have a tool that is similar to what most orgs have as their internal tool, from the people that joined our calls last semester and from my research it seems like most companies have an internal tool (from my findings more than half of series c companies). No company wants to build an internal tool for open source management but if there's no product that meats their requirements then they must spend $1,000,000+ to build and maintain. Hopefully by the end of this, this tool could be something that companies would be willing to use instead of building their own tool, also having devs join our calls and asking them about their companies open source needs and tools could help define other requirements.

