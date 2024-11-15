---
layout: post
title: My Cybersecurity PATH
date: 2024-11-10 13:32:20 +0300
description: Get It? PATH?
image: /assets/images/hacker.jpg
fig-caption: # Add figcaption (optional)
tags: [personal, professional]
---

 It's occasionally said within the field that, "There are no entry-level jobs in cybersecurity," but from a brief glance at my resume, I could be considered an exception. To that point, I figured it would make sense to explain myself, because the truth is that I can see evidence of someone creating my own experience from an early age. I think the key wass not just the concrete steps I took deliberately, but also the context of what I learned early on. If you just want to know what I did *after** I decided to get into IT and eventually cybersecurity, you can safely skip to [COVID-19 and Beyond](https://cagrigsby.github.io/2024/08/10/break-into-cybersecurity.html#COVID-19-and-beyond). 

## Adolescent Tinkering
I'd like to start before college. After all, infosec professionals do not exist in a vaccuum...and neither do I. I think at this point it's not unexpected for security types to have gotten their start in engineering or hacking of some kind before even going to college. You certainly hear of teenage hackers, and there are high schools (not mine) with coding courses. I've even seen evidence of a high school digital forensics class, though I assume it must be some kind of special elective. I didn't have any of that, but I *did* have an interest in using computers in ways outside their expected use. Not so long ago, it was actually difficult and expensive to find everything you wanted. 

I discovered what I know now are called Insecure Direct Object References (IDOR) and Directory Traversal simply by browsing the web for galleries and open directories. And it was always a jackpot to find someone's unsecured FTP server full of movies. Like many others, my frist experience with ~~Frankensteining~~ writing code was Myspace and HTML. Before YouTube, it wasn't uncommon for websites to host their own media files which you could download by getting into the source code and finding the asset referenced. I remember using [this page](http://www.therapboard.com/) to download rapper's catchphrases to use as text tones for my friends. I'm honestly surprised it's still up. Looking for music is how I learned about Google Dorking, though there were certainly sketchier techniques we don't need to get into. I had to have few to sell bootleg leaks. And I think my first experience with the command line involved jailbreaking phones. That's unless you count the [hacking minigame](https://www.youtube.com/watch?v=2jNH1e3akjg) from the Gamecube/PS2/Xbox game Enter the Matrix, which you definitely don't because if you've ever even heard of it, you haven't thought about it in a decade. 

To be honest, those are some of the tamer examples, but hey my name is on here. I'm not giving them because I think they're interesting; I'm just painting a picture of someone who, looking back, was primed to learned about cybersecurity. Most people I knew back then didn't do any of that stuff, so when I talk about starting from zero, I just want to be clear that **my zero may not be the same as your zero**. I had a computer from a young age, and I have to acknowledge it was a specific time in history when everything was online, you still needed to find it. There was value in discovering how the web worked, and I sought it out more than my peers. 

## Early Career
I don't think is a single thing that I did professionially in my first 10 years out of college that informed my subsequent interest in cybersecurity. I guess I made a couple of Wordpress blogs over the years. , and I took 8% of a SQL course thinking it might help me with my dead end job in support for a broken SaaS product. It didn't, and it wouldn't have. 

After college I taught English in the [Republic of Georgia](https://en.wikipedia.org/wiki/Georgia_(country)), I was a nanny, I worked in the service industry, I drove rideshare, and I backpacked in New Zealand picking blueberries, cleaing toilets, and working at a ski resort. None of these had anything to do with information security in particular, or tech in general. Terrific life experience, but poor work experience. 

## COVID-19 and Beyond
In January of 2020, I accepted a job in marketing for an event space/creative studio which ultimately never even got off the ground due the to COVID-19 pandemic. I was lucky to have some severance and a place to stay, both of which bought me enough time to figure out my next steps. After a peek into the mortgage lending industry, I was recommended an aptitude test through [YouScience](https://www.youscience.com/buy-now/), which pointed me towards IT. With time on my hands, I figured I'd give a shot, getting started with [Google's IT Support Professional Certificate](https://www.coursera.org/professional-certificates/google-it-support). I enjoyed it, and I especially enjoyed the section on IT Security. At that point, I decided to focus my efforts. A short list of my efforts:

1. Going throough [Automate The Boring Stuff with Python](https://automatetheboringstuff.com/), completing all the exercises. 
2. An Intro to SQL course with [Mammoth Interactive](https://training.mammothinteractive.com/)
3. Completing [IBM's Cybersecurity Analyst Professional Certificate](https://www.coursera.org/professional-certificates/ibm-cybersecurity-analyst)(do not recommend)
4. Completing [CompTIA's Security+ certification](https://www.comptia.org/certifications/security)
5. Completing a ton of [TryHackMe](https://tryhackme.com/p/grica421) rooms/paths such the Pre Security, Introduction to Cyber Security, and Pentest+ paths, though they may have been called something else at the time
6. General computer coding courses through [Khan Academy](https://www.khanacademy.org/) with some SQL and JS in particular
7. [This](https://github.com/PIVOT-Project/DigitalForensicsChallenge) previously referenced digital forensics exercise (I cannot find the original link)

At some point I started reaching out to others for help. I didn't really know anyone in cybersecurity at the time (though I later discovered a relative I didn't know was), so I reached out to someone over reddit who was recommending someone else not do a boot camp. He suggested that I create an AWS account and write some scripts to prove that I could appy some of what I had learned. I wrote a Lambda function to send AWS GuardDuty alerts to slack, and eventually a CloudFormation template to install it. I put them on my first [github](https://github.com/cagrigsby/guardduty2slack), along with [my first scripts](https://github.com/cagrigsby/my-first-scripts) to check whether a Linux user has changed their password in the last 30 days. Note that these were pre-ChatGPT, not that that makes them particularly impressive. 

## I'm In (Hacker Voice)
At this point, I got my first job as a Cybersecurity Consultant! I was ecstatic but not finished. I really, really enjoy the field, and you kind of have to keep learning to stay on top of it. Since I was first hired, I got my [AWS Certified Cloud Practitioner](https://aws.amazon.com/certification/certified-cloud-practitioner/), [AWS Solutions Architect Associate](https://aws.amazon.com/certification/certified-solutions-architect-associate/), [CompTIA CySA+](https://www.comptia.org/certifications/cybersecurity-analyst), and my favorite, the Ethical Junior Penetration Tester certification from INE Security, or [eJPT](https://security.ine.com/certifications/ejpt-certification/). This lesser known certification is a practical exam which helped me prepare for my current goal, the OSCP. It, along with the 100+ hours of other online training, most notably through TryHackMe, made me feel like I was finally ready to begin prepping for the OSCP.

## OSCP
I started seriously focusing on the OSCP in April 2024, and it was quite the learning experience. I will probably split that off into another post, but I was just wasn't as ready as I thought. I went through Offsec's entire [PEN-200](https://www.offsec.com/courses/pen-200/) course, as well as all of the Practice Labs. There's a lot of good information there, but after doing some research on what else to study, I went through the majority of [TJ Null's PEN-200 list of labs](https://docs.google.com/spreadsheets/u/1/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/htmlview#) and [LainKusanagi's list of OSCP like machines](https://docs.google.com/spreadsheets/d/18weuz_Eeynr6sXFQ87Cd5F0slOj9Z6rt/edit?gid=487240997#gid=487240997). I even took the PEN-200 labs again to check my progress, which despite the additional cost felt very worthwhile. And all my practicing paid off because I was finally able to pass the exam in November 2024!

## Future Plans
When I first started studying for the OSCP, I would occasionally see reviews of the exam and bristle when I read posts saying it was entry-level. Maybe I felt threatened to be struggling with what others considered beginner material. By the time I was actually prepared and ready to pass, I understood what they meant. There's just so much to learn, and the techniques taught for the exam only scratch the surface. But instead of being threatened I find it thrilling to keep going. 

I think the next couple certifications will be the [Burp Suite Certified Practitioner](https://portswigger.net/web-security/certification), the material of which I have already begun studying due to the OSCP, and the [CompTIA Pentest+](https://www.comptia.org/certifications/pentest), mostly because it will auto-renew my other CompTIA certs. I also want to learn more about Physcial Security. I've got a lockpick kit, I fiddle with that when I got a chance, and there is a [IoT and Hardware Hacking](https://academy.tcm-sec.com/p/beginner-s-guide-to-iot-and-hardware-hacking) course through The Cyber Mentor that looks cool. I think that's a lot to chew on for now, but the fun part is that there's just so much out there to learn, so I never need to get stagnant in one area. I'ts probably my favorite thing about cybersecurity, and it's been so much **fun** to learn, something I never really thought I'd be able to say. Hopefully that sheds some light on my background and maybe even gives someone else some ideas on what they could do. As always, feel free to reach out! I'd love to be able to help!