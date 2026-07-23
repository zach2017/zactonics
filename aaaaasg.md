# AWS Auto Scaling Groups + Networking: The Complete Beginner Tutorial

*Written so a middle schooler can follow it, but detailed enough for a real job.*

---

## Table of Contents

1. [The Big Idea (What and Why)](#1-the-big-idea-what-and-why)
2. [Vocabulary You Need First](#2-vocabulary-you-need-first)
3. [Networking Background (VPC, Subnets, AZs)](#3-networking-background-vpc-subnets-azs)
4. [Step-by-Step: Build Your First Auto Scaling Group](#4-step-by-step-build-your-first-auto-scaling-group)
5. [How Scaling Actually Works Under the Hood](#5-how-scaling-actually-works-under-the-hood)
6. [All the Scaling Policy Types (Pros and Cons)](#6-all-the-scaling-policy-types-pros-and-cons)
7. [Health Checks and Instance Replacement](#7-health-checks-and-instance-replacement)
8. [Networking Deep Dive for ASGs](#8-networking-deep-dive-for-asgs)
9. [Saving Money: Spot, Mixed Instances, Warm Pools](#9-saving-money-spot-mixed-instances-warm-pools)
10. [Updating Your App Safely (Instance Refresh)](#10-updating-your-app-safely-instance-refresh)
11. [Alternatives to Auto Scaling Groups](#11-alternatives-to-auto-scaling-groups)
12. [Pros and Cons of ASGs Overall](#12-pros-and-cons-of-asgs-overall)
13. [Troubleshooting Guide](#13-troubleshooting-guide)
14. [Gotchas That Bite Everyone](#14-gotchas-that-bite-everyone)
15. [Best Practices Checklist](#15-best-practices-checklist)
16. [Cleanup (Don't Skip This)](#16-cleanup-dont-skip-this)
17. [Cheat Sheet](#17-cheat-sheet)

---

## 1. The Big Idea (What and Why)

### The pizza shop story

Imagine you run a pizza shop.

- On a normal Tuesday, **2 cooks** handle all the orders fine.
- On Friday night, **200 people** show up. Two cooks can't keep up. Orders take an hour. Customers leave angry.
- On Monday morning, almost nobody comes in. But you're still paying **10 cooks** to stand around doing nothing.

You have two problems: **not enough workers when it's busy**, and **too many workers when it's quiet**.

A perfect solution would be a magic system that:
- Watches how busy the kitchen is
- Calls in more cooks automatically when things get crazy
- Sends cooks home automatically when it slows down
- Notices if a cook faints, and calls a replacement immediately

**That magic system is an AWS Auto Scaling Group (ASG).** The "cooks" are EC2 virtual servers.

### What an Auto Scaling Group actually is

An **Auto Scaling Group** is a manager that owns a group of identical EC2 instances (virtual computers) and keeps the right number of them running.

You give it three numbers:

| Setting | Meaning | Pizza shop version |
|---|---|---|
| **Minimum** | Never go below this many | "Always keep at least 2 cooks" |
| **Desired** | How many I want *right now* | "Right now, 4 cooks" |
| **Maximum** | Never go above this many | "Never more than 10 cooks, I can't afford it" |

Then the ASG does three jobs, forever, without you watching:

1. **Keeps the count correct.** If desired is 4 and only 3 are running, it launches one.
2. **Replaces broken servers.** If a server dies or fails a health check, it terminates it and launches a fresh one.
3. **Changes the desired count based on rules.** Traffic spikes → add servers. Traffic drops → remove servers.

### Why you should care (the "why")

| Benefit | What it means in real life |
|---|---|
| **High availability** | A server crashes at 3 AM. ASG replaces it before you even wake up. |
| **Fault tolerance** | An entire AWS data center loses power. ASG rebuilds your servers in a different data center. |
| **Elasticity** | Black Friday traffic is 20x normal. Your site stays fast. |
| **Cost savings** | At 3 AM you run 2 servers instead of 20. You pay for what you use. |
| **Free** | The ASG service itself costs $0. You only pay for the EC2 instances it launches. |
| **Cattle, not pets** | You stop caring about individual servers. Any one can die and be replaced. This changes how you work forever. |

> **Key mental shift:** Before ASGs, servers were **pets** — you named them, nursed them back to health when sick, and panicked when one died. With ASGs, servers are **cattle** — numbered, identical, disposable. If one is sick, you replace it. This is the single most important idea in modern cloud infrastructure.

---

## 2. Vocabulary You Need First

Learn these 12 words and the rest of the tutorial is easy.

| Term | Plain-English meaning |
|---|---|
| **EC2 instance** | A virtual computer you rent from Amazon by the second. |
| **AMI** (Amazon Machine Image) | A snapshot/photocopy of a hard drive. Used as the "cookie cutter" to stamp out new identical servers. |
| **Instance type** | The size of the computer. `t3.micro` = tiny and cheap. `c7g.4xlarge` = big and expensive. |
| **Region** | A geographic area, like `us-east-1` (Virginia) or `eu-west-1` (Ireland). |
| **Availability Zone (AZ)** | A separate physical data center inside a Region, like `us-east-1a`. There are usually 3–6 per Region. They have separate power and cooling. |
| **VPC** (Virtual Private Cloud) | Your own private network inside AWS. Like your own fenced-in neighborhood. |
| **Subnet** | A smaller street inside your VPC neighborhood. Each subnet lives in exactly one AZ. |
| **Security Group** | A firewall around each server. "Only allow web traffic in." |
| **Launch Template** | The recipe card: which AMI, which instance type, which security group, what startup script. |
| **Load Balancer (ALB)** | A traffic cop that spreads incoming visitors across all your servers. |
| **Target Group** | The list of servers the load balancer is allowed to send traffic to. |
| **CloudWatch** | AWS's monitoring system. It collects metrics like "CPU is at 80%" and can trigger alarms. |
| **User data** | A startup script that runs the first time a server boots. This is how a blank server becomes your web server. |

---

## 3. Networking Background (VPC, Subnets, AZs)

You cannot understand ASGs without understanding where servers *live*. Let's build the mental picture.

### The neighborhood diagram

```
REGION: us-east-1 (Northern Virginia)
│
└── VPC: 10.0.0.0/16  ← your private network, ~65,000 addresses
    │
    ├── Availability Zone us-east-1a  (Data Center #1)
    │   ├── Public Subnet  10.0.1.0/24   ← Load balancer lives here
    │   └── Private Subnet 10.0.11.0/24  ← Your app servers live here
    │
    ├── Availability Zone us-east-1b  (Data Center #2)
    │   ├── Public Subnet  10.0.2.0/24
    │   └── Private Subnet 10.0.12.0/24
    │
    └── Availability Zone us-east-1c  (Data Center #3)
        ├── Public Subnet  10.0.3.0/24
        └── Private Subnet 10.0.13.0/24
```

### Why this shape?

**Why multiple AZs?**
Each AZ is a physically separate building, miles apart, with its own power, internet, and cooling. If a tornado hits `us-east-1a`, the servers in `us-east-1b` and `us-east-1c` keep working. **Spreading your ASG across at least 2 AZs (ideally 3) is the #1 reliability rule in AWS.**

**Why public vs. private subnets?**

| | Public Subnet | Private Subnet |
|---|---|---|
| Has a route to an **Internet Gateway** | ✅ Yes | ❌ No |
| Can be reached directly from the internet | ✅ Yes | ❌ No |
| Can reach *out* to the internet | ✅ Yes | Only via a **NAT Gateway** |
| What goes here | Load balancers, NAT gateways, bastion hosts | App servers, databases |

**The security logic:** Put your app servers in **private** subnets. Nobody on the internet can connect to them directly. The only way in is through the load balancer, which sits in the public subnet and only forwards proper web traffic. This is called **defense in depth**.

### CIDR blocks (the address math)

`10.0.0.0/16` looks scary. Here's the trick:

- An IP address has 32 bits.
- The `/16` means "the first 16 bits are locked; the rest are free for addresses."
- 32 − 16 = 16 free bits = 2¹⁶ = **65,536 addresses**.
- `/24` means 32 − 24 = 8 free bits = **256 addresses**.

| CIDR | Usable addresses in AWS | Good for |
|---|---|---|
| `/16` | ~65,531 | A whole VPC |
| `/20` | ~4,091 | A big subnet |
| `/24` | **251** | A normal subnet |
| `/28` | **11** | Tiny subnet (minimum AWS allows) |

> ⚠️ **AWS steals 5 IPs from every subnet** (network address, VPC router, DNS, future use, broadcast). So a `/24` gives you 251 usable, not 256. This matters when your ASG tries to scale to 300 instances in a `/24` and mysteriously stops at 251.

### The three networking rules that break ASGs

These cause more failures than anything else. Memorize them.

1. **Security Groups** are stateful allow-lists on each server. If your health check fails, this is usually why.
2. **Network ACLs (NACLs)** are stateless allow-lists on each *subnet*. Because they're stateless, you must allow **return traffic on ephemeral ports 1024–65535** in the outbound rules. Forgetting this is a classic bug.
3. **Route Tables** decide where packets go. A private subnet with no NAT Gateway route means your instance can't download packages, can't reach the internet, and your startup script silently fails.

---

## 4. Step-by-Step: Build Your First Auto Scaling Group

We'll build a real, working, self-healing web site. Everything here fits in the **AWS Free Tier** if you clean up afterward.

**What we're building:**

```
Internet
   │
   ▼
Application Load Balancer  (public subnets, 2 AZs)
   │
   ├──────────────┬──────────────┐
   ▼              ▼              ▼
 EC2 #1         EC2 #2        EC2 #3     ← managed by the ASG
(us-east-1a)  (us-east-1b)  (us-east-1a)   (private subnets)
```

**Time needed:** about 25 minutes.

---

### Step 0 — Prerequisites

- An AWS account (a personal one, not your company's production account).
- Log in as an IAM user, **not** the root account.
- Set your Region to **us-east-1** (top-right corner of the console) so screenshots and names match.
- You should already have a VPC with **at least 2 subnets in 2 different AZs**. Every new AWS account gets a **default VPC** with one public subnet per AZ — that's fine for this tutorial.

---

### Step 1 — Create a Security Group for the Load Balancer

1. Console → **EC2** → left sidebar → **Security Groups** → **Create security group**
2. Name: `tutorial-alb-sg`
3. Description: `Allows web traffic from the internet to the ALB`
4. VPC: pick your default VPC
5. **Inbound rules** → Add rule:
   - Type: `HTTP`, Port: `80`, Source: `Anywhere-IPv4 (0.0.0.0/0)`
6. Leave outbound rules as-is (allow all)
7. **Create security group**

**Why:** This firewall says "anyone on the internet may talk to the load balancer on port 80."

---

### Step 2 — Create a Security Group for the App Servers

1. **Create security group** again
2. Name: `tutorial-app-sg`
3. VPC: same default VPC
4. **Inbound rules** → Add rule:
   - Type: `HTTP`, Port: `80`
   - Source: **Custom** → start typing `tutorial-alb-sg` and select it

> 🔑 **This is the most important step in the whole tutorial.** You are *not* allowing the internet in. You are allowing **only the load balancer's security group** in. This is called **security group chaining**. Even if someone learns your server's IP address, they cannot reach it. This is what real production setups do.

5. **Create security group**

---

### Step 3 — Create a Launch Template

The Launch Template is the recipe for every server the ASG will bake.

1. EC2 → left sidebar → **Launch Templates** → **Create launch template**
2. **Name:** `tutorial-web-lt`
3. **Template version description:** `v1 - simple nginx page`
4. ✅ Check **"Provide guidance to help me set up a template that I can use with EC2 Auto Scaling"**
5. **Application and OS Images:** choose **Amazon Linux 2023 AMI** (it's free-tier eligible and marked "Free tier eligible")
6. **Instance type:** `t3.micro` (or `t2.micro` if `t3.micro` isn't free-tier in your account)
7. **Key pair:** select **"Don't include in launch template"**
   - *Why:* modern practice is to use **AWS Systems Manager Session Manager** for shell access instead of SSH keys. Fewer keys = fewer things to lose.
8. **Network settings:**
   - Subnet: **"Don't include in launch template"** ← ⚠️ critical, the ASG picks subnets, not the template
   - Security groups: select **`tutorial-app-sg`**
9. Expand **Advanced details** → scroll to the bottom → **User data** box → paste:

```bash
#!/bin/bash
dnf update -y
dnf install -y nginx
systemctl enable nginx
systemctl start nginx

# Show which instance and which AZ served the page
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
IID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/instance-id)
AZ=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/placement/availability-zone)

cat > /usr/share/nginx/html/index.html <<EOF
<!doctype html>
<html><head><title>ASG Tutorial</title></head>
<body style="font-family:sans-serif;text-align:center;padding-top:60px">
  <h1>Hello from the Auto Scaling Group!</h1>
  <p><b>Instance ID:</b> $IID</p>
  <p><b>Availability Zone:</b> $AZ</p>
</body></html>
EOF

# A dedicated health check endpoint (best practice)
echo "OK" > /usr/share/nginx/html/health

systemctl restart nginx
```

10. **Create launch template**

> 📝 **What just happened:** User data is a script that runs **once**, as root, the very first time an instance boots. This turns a blank Amazon Linux server into your web server automatically. That `169.254.169.254` address is the **Instance Metadata Service** — a magic local address every EC2 instance can query to learn about itself. The `TOKEN` part is **IMDSv2**, the secure version. Always use IMDSv2.

---

### Step 4 — Create the Target Group

1. EC2 → left sidebar → **Target Groups** → **Create target group**
2. Target type: **Instances**
3. Name: `tutorial-tg`
4. Protocol: `HTTP`, Port: `80`
5. VPC: your default VPC
6. Protocol version: `HTTP1`
7. **Health checks:**
   - Protocol: `HTTP`
   - Path: `/health` ← the file our user data script created
8. Expand **Advanced health check settings** and set:
   - Healthy threshold: `2`
   - Unhealthy threshold: `2`
   - Timeout: `5` seconds
   - Interval: `10` seconds
   - Success codes: `200`
9. **Next** → **do not register any targets** (the ASG will do this) → **Create target group**

> 💡 **Why a `/health` path instead of `/`?** If your homepage does a slow database query, a hiccup in the database would make every server look "unhealthy," and the ASG would kill your entire fleet. A dedicated health endpoint that just returns `OK` tests "is the web server alive," which is what you actually want.

---

### Step 5 — Create the Application Load Balancer

1. EC2 → left sidebar → **Load Balancers** → **Create load balancer** → **Application Load Balancer**
2. Name: `tutorial-alb`
3. Scheme: **Internet-facing**
4. IP address type: `IPv4`
5. **Network mapping:** select your VPC, then **check at least 2 Availability Zones** and pick a public subnet in each
6. **Security groups:** select `tutorial-alb-sg` (remove the default one)
7. **Listeners and routing:** Protocol `HTTP`, Port `80` → Default action: **Forward to `tutorial-tg`**
8. **Create load balancer**
9. Wait ~2–3 minutes until State shows **Active**. Copy the **DNS name** (looks like `tutorial-alb-123456789.us-east-1.elb.amazonaws.com`).

---

### Step 6 — Create the Auto Scaling Group ⭐

1. EC2 → left sidebar → **Auto Scaling Groups** → **Create Auto Scaling group**

**Page 1 — Name and template**
- Name: `tutorial-asg`
- Launch template: `tutorial-web-lt`, Version: `Latest`
- **Next**

**Page 2 — Network**
- VPC: your default VPC
- Availability Zones and subnets: **select subnets in at least 2 different AZs**
- Availability Zone distribution: **Balanced best effort**
- **Next**

**Page 3 — Load balancing**
- Choose **Attach to an existing load balancer**
- **Choose from your load balancer target groups** → select `tutorial-tg`
- **Turn ON** ✅ **Turn on Elastic Load Balancing health checks**
- **Health check grace period:** `300` seconds
- **Next**

> ⏱️ **Grace period explained:** After a new server boots, it needs time to install nginx and start up. The grace period tells the ASG "don't judge this server's health for the first 300 seconds." Set this **too short** and the ASG kills servers while they're still starting, then launches replacements that also get killed — an infinite **launch loop** that burns money. Set it **too long** and genuinely broken servers stick around. Rule of thumb: measure your real boot time, then double it.

**Page 4 — Group size and scaling**
- Desired capacity: `2`
- Min desired capacity: `2`
- Max desired capacity: `6`
- **Automatic scaling:** choose **Target tracking scaling policy**
  - Metric type: **Average CPU utilization**
  - Target value: `50`
  - Instance warmup: `300` seconds
- Instance maintenance policy: leave default
- **Next**

**Page 5 — Notifications** → skip → **Next**

**Page 6 — Tags** → Add tag: Key `Name`, Value `tutorial-web-server` ✅ Tag new instances → **Next**

**Page 7 — Review** → **Create Auto Scaling group**

---

### Step 7 — Watch It Work

1. Go to EC2 → **Instances**. Within about a minute you'll see **2 new instances** launching, tagged `tutorial-web-server`. Note they're in **different AZs**.
2. Go to **Target Groups** → `tutorial-tg` → **Targets** tab. Watch status go `initial` → **`healthy`** (takes 2–4 minutes).
3. Paste the ALB DNS name into your browser. You should see your page!
4. **Refresh several times.** The Instance ID and AZ change — proof the load balancer is spreading traffic across servers in different data centers.

---

### Step 8 — Test Self-Healing (the fun part) 🔥

1. EC2 → **Instances** → select one of your two instances
2. **Instance state** → **Terminate instance** → confirm

Now watch:

| Time | What happens |
|---|---|
| 0:00 | You terminate the instance |
| 0:10 | Target group marks it `draining`, ALB stops sending it traffic |
| 0:30 | ASG notices desired=2 but only 1 running |
| 0:45 | ASG launches a brand-new replacement |
| 3:00 | Replacement passes health checks, starts receiving traffic |

Your website **never went down**. The load balancer routed everything to the surviving server the whole time. You did nothing. **That is the entire point of Auto Scaling Groups.**

---

### Step 9 — Test Scaling Out

Force the CPU high so the scaling policy fires.

1. Connect to an instance: EC2 → Instances → select one → **Connect** → **Session Manager** tab → **Connect**
2. Run:

```bash
# Burn 100% CPU on all cores for 10 minutes
sudo dnf install -y stress-ng
stress-ng --cpu 0 --timeout 600s
```

3. Go to your ASG → **Monitoring** tab, and CloudWatch → Alarms.
4. After roughly **3–5 minutes** of high CPU, the alarm fires and the ASG raises desired capacity. New instances appear.
5. When the stress test ends, CPU drops. After about **15 minutes** of low CPU, the ASG scales back down to 2.

> 📉 **Notice the asymmetry:** scaling **out** is fast (~3 min), scaling **in** is slow (~15 min). This is deliberate. Being slow to add servers means a bad user experience. Being slow to remove them costs a few cents. AWS optimizes for the user experience. This is called **aggressive scale-out, conservative scale-in**, and you should keep it that way.

---

## 5. How Scaling Actually Works Under the Hood

Understanding the loop makes troubleshooting 10x easier.

```
┌──────────────────────────────────────────────────────────────┐
│  1. EC2 instances publish metrics to CloudWatch every 60s    │
│         (or every 10s if Detailed Monitoring is on)          │
└──────────────────────────────┬───────────────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────────┐
│  2. A CloudWatch Alarm watches the metric.                   │
│     "CPU > 50% for 3 consecutive periods" → ALARM state      │
└──────────────────────────────┬───────────────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────────┐
│  3. Alarm triggers the ASG's scaling policy.                 │
│     ASG changes DESIRED CAPACITY from 2 → 4                  │
└──────────────────────────────┬───────────────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────────┐
│  4. ASG sees desired(4) > running(2). Launches 2 instances   │
│     using the Launch Template, into the least-loaded AZs.    │
└──────────────────────────────┬───────────────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────────┐
│  5. New instances boot → run user data → register with the   │
│     Target Group → pass health checks → receive traffic.     │
└──────────────────────────────┬───────────────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────────┐
│  6. WARMUP / COOLDOWN period: ASG ignores metrics briefly so │
│     it doesn't overreact before the new servers help.        │
└──────────────────────────────┬───────────────────────────────┘
                               ▼
                    Loop back to step 1, forever
```

### The instance lifecycle

Every instance passes through these states:

```
Pending → Pending:Wait → Pending:Proceed → InService
                                              │
                                              ▼
                             Terminating:Wait → Terminating:Proceed → Terminated
                                              │
                                              └──→ Standby (manual pause)
```

- **`Pending:Wait` / `Terminating:Wait`** only appear if you use a **Lifecycle Hook** — a pause button that lets you run custom code (load config, drain connections, upload logs) before an instance joins or leaves. Very useful, often forgotten.
- **`Standby`** lets you pull an instance out of service for debugging **without** the ASG replacing it. Great for investigating a weird server.

### Which instance gets terminated on scale-in?

The **Termination Policy**, in order:

1. **Balance across Availability Zones** (always first — the ASG picks from the AZ with the most instances)
2. Then, within that AZ, the default policy picks the instance with the **oldest launch template/configuration**
3. Tie-break: the instance **closest to the next billing hour**
4. Final tie-break: **random**

You can override with policies like `OldestInstance`, `NewestInstance`, `ClosestToNextInstanceHour`, `AllocationStrategy`, or a **custom Lambda function**.

> ⚠️ **The AZ-balance rule beats everything.** If you have 3 old instances in `us-east-1a` and 1 new one in `us-east-1b`, scale-in takes one from `1a` — even if you told it `NewestInstance`. This surprises people constantly.

---

## 6. All the Scaling Policy Types (Pros and Cons)

There are five ways to change capacity. Pick deliberately.

---

### 6.1 Target Tracking Scaling ⭐ *(start here)*

**How it works:** You say "keep average CPU at 50%." AWS builds the alarms and does the math for you. It's like a thermostat: you set the temperature, the system figures out the furnace.

```json
{
  "PolicyType": "TargetTrackingScaling",
  "TargetTrackingConfiguration": {
    "PredefinedMetricSpecification": {
      "PredefinedMetricType": "ASGAverageCPUUtilization"
    },
    "TargetValue": 50.0
  }
}
```

Built-in metrics available:
| Metric | Use when |
|---|---|
| `ASGAverageCPUUtilization` | CPU-bound apps (image processing, computation) |
| `ALBRequestCountPerTarget` | Web apps — **often the best choice** |
| `ASGAverageNetworkIn` / `Out` | Data-transfer-heavy apps |
| Any custom CloudWatch metric | Queue depth, active connections, etc. |

**✅ Pros**
- Simplest to set up — one number
- AWS auto-creates and tunes the CloudWatch alarms
- Scales out fast, scales in gently, automatically
- Won't scale in if that would push the metric past the target

**❌ Cons**
- Only tracks **one** metric per policy
- You can't control the exact step sizes
- Poor fit for metrics that don't go down when you add instances (see gotcha below)

**🎯 Best for:** 90% of web applications. **This should be your default.**

> ⚠️ **Critical gotcha:** Target tracking requires a metric that **decreases when you add instances**. `ALBRequestCountPerTarget` works (more targets = fewer requests each). Raw `RequestCount` does **not** work — adding servers doesn't reduce total requests, so the ASG will scale to max and stay there.

---

### 6.2 Step Scaling

**How it works:** You define alarm thresholds and different-sized responses for each severity band.

```
CPU 50–60% → add 1 instance
CPU 60–80% → add 2 instances
CPU 80%+   → add 4 instances
```

**✅ Pros**
- Fine-grained control over emergency response
- Handles sudden, sharp spikes better than target tracking
- Multiple policies can coexist (the biggest adjustment wins)

**❌ Cons**
- You must build and tune every alarm yourself
- Easy to misconfigure into oscillation (flapping)
- Much more work to maintain

**🎯 Best for:** Traffic with sudden violent spikes where you need to jump many instances at once.

---

### 6.3 Simple Scaling *(legacy — avoid)*

**How it works:** One alarm, one action, then a mandatory cooldown where nothing else can happen.

**✅ Pros** — Easy to understand.

**❌ Cons** — The cooldown **blocks all other scaling activity**. If traffic keeps climbing during the cooldown, you're stuck undersized. Step scaling does everything Simple does but better.

**🎯 Best for:** Nothing new. AWS itself recommends step or target tracking instead.

---

### 6.4 Scheduled Scaling

**How it works:** Change min/max/desired at specific times using cron syntax.

```bash
aws autoscaling put-scheduled-update-group-action \
  --auto-scaling-group-name tutorial-asg \
  --scheduled-action-name weekday-morning-rush \
  --recurrence "0 8 * * MON-FRI" \
  --time-zone "America/New_York" \
  --min-size 10 --desired-capacity 12 --max-size 30
```

**✅ Pros**
- Servers are ready **before** the rush, not 5 minutes late
- Perfect for predictable patterns (office hours, batch jobs, school schedules)
- Great cost saver: scale dev environments to 0 at night

**❌ Cons**
- Blind to reality — it fires whether or not traffic actually arrived
- Timezone/DST mistakes are common
- Needs updating when patterns change

**🎯 Best for:** **Combine with target tracking.** Scheduled sets the floor; target tracking handles surprises. This combo is a production best practice.

---

### 6.5 Predictive Scaling

**How it works:** Machine learning studies **14 days** of your traffic history, forecasts the next 48 hours, and pre-launches capacity ahead of predicted demand. Forecasts refresh hourly.

**✅ Pros**
- Solves the "warm-up lag" problem — capacity arrives *before* the spike
- Zero manual tuning
- Free
- Has a **Forecast Only** mode so you can watch it for weeks before trusting it

**❌ Cons**
- Needs **at least 24 hours** of data; wants 14 days for good accuracy
- Only useful for **cyclical, repeating** patterns
- Useless for random or brand-new workloads
- Can over-provision if you have an unusual week

**🎯 Best for:** Established apps with daily/weekly rhythms and long boot times. **Always pair with target tracking** — prediction handles the expected, target tracking catches the unexpected.

---

### Comparison table

| Policy | Setup effort | Reaction speed | Handles surprises | Cost efficiency | Recommendation |
|---|---|---|---|---|---|
| Target Tracking | ⭐ Very easy | Fast | ✅ Yes | Good | **Default choice** |
| Step Scaling | Hard | Fastest | ✅ Yes | Good if tuned | For violent spikes |
| Simple Scaling | Easy | Slow | ⚠️ Poor | Poor | Don't use |
| Scheduled | Easy | Instant (on time) | ❌ No | Excellent | Pair with target tracking |
| Predictive | Easy | Ahead of time | ❌ No | Excellent | Pair with target tracking |

> 🏆 **The production-grade combo:** **Predictive** (or Scheduled) + **Target Tracking**. Prediction sets a smart baseline; target tracking is the safety net.

---

## 7. Health Checks and Instance Replacement

The ASG can use several sources of truth about whether an instance is alive.

| Health check type | What it tests | Catches |
|---|---|---|
| **EC2** (always on) | Is the VM running? Do AWS's system + instance status checks pass? | Hardware failure, kernel panic, network loss |
| **ELB** (turn this on!) | Does the target group say healthy? | ✅ Your app crashed but the OS is fine |
| **VPC Lattice** | Lattice target health | Service-mesh setups |
| **EBS** | Attached volume health | Storage failure |
| **Custom** | You call the API and declare health | Anything you want |

### Why ELB health checks matter so much

Picture this: your Java app runs out of memory and dies. The Linux server is perfectly fine — it's running, pinging, everything green.

- **EC2 health check only:** "Instance is running. It's healthy!" → The ASG leaves a dead app in service forever. Users get errors.
- **ELB health check on:** "Port 80 isn't responding to `/health`." → Marked unhealthy → terminated → replaced. Automatically.

> ✅ **Always enable ELB health checks when using a load balancer.** This one checkbox is the difference between "self-healing" and "self-deceiving."

### Designing a good health check endpoint

| ❌ Bad | ✅ Good |
|---|---|
| Path `/` that renders the full homepage | Path `/health` that returns `200 OK` |
| Checks the database, cache, and 3 APIs | Checks only "is this process serving requests?" |
| Takes 4 seconds to respond | Responds in under 50 ms |
| Timeout 2s, threshold 1 | Timeout 5s, unhealthy threshold 2 |

**Why not check the database?** If your database has a 30-second blip, *every* server fails its health check simultaneously. The ASG terminates your entire fleet, then the replacements also fail, and you've turned a 30-second database hiccup into a total outage. This has taken down real companies.

Use two endpoints if you need depth:
- `/health` — **liveness**: "Am I running?" → used by the ASG/ALB
- `/ready` — **readiness with dependencies** → used by dashboards and alerts, *not* by the terminator

---

## 8. Networking Deep Dive for ASGs

### Subnet capacity math (the silent scaling ceiling)

Every instance consumes **at least one private IP**. Some setups consume many more:

| Setup | IPs per instance |
|---|---|
| Basic EC2 | 1 |
| EC2 + secondary IPs | 1 + extras |
| EKS with VPC CNI | Can be **dozens** (pre-allocated per pod) |

**Worked example:** You have a `/27` subnet = 32 addresses − 5 reserved = **27 usable**. Your ASG max is 50. You'll hit a hard wall at 27 and see:

```
Launch failed: There are not enough free addresses in subnet
subnet-0abc123 to satisfy the requested number of instances.
```

**Fix:** size subnets generously up front (`/22` or `/20` is common for app tiers). You **cannot resize a subnet** after creation — you have to make a new one. Plan ahead.

### NAT Gateway: the invisible bill

Private-subnet instances reach the internet through a **NAT Gateway**.

| Cost item | Approximate price |
|---|---|
| NAT Gateway hourly | ~$0.045/hour ≈ **$32/month each** |
| Data processed | ~$0.045 per GB |

**The trap:** best practice says one NAT Gateway **per AZ** (so an AZ failure doesn't kill the others). Three AZs = ~**$100/month before any traffic**. Then your ASG scales to 100 instances, each pulling 500 MB of packages on boot = 50 GB = another $2.25, plus ongoing traffic.

**Ways to cut it:**
1. **VPC Endpoints** — S3 and DynamoDB **Gateway endpoints are free** and bypass NAT entirely. Use them always.
2. **Interface endpoints** for ECR, SSM, CloudWatch, Secrets Manager (these cost ~$7/mo each but are usually cheaper than NAT data charges at scale).
3. **Bake dependencies into your AMI** so instances don't download packages on every boot. Also makes boots much faster.
4. **Dev/test only:** a single shared NAT Gateway (accepting the AZ-failure risk).

### Public vs. private placement

| | Instances in public subnets | Instances in private subnets |
|---|---|---|
| Setup complexity | Simple | Needs NAT Gateway |
| Cost | Cheaper (no NAT) | +$32/mo per NAT |
| Security | ⚠️ Exposed to internet scanning | ✅ Unreachable from internet |
| Verdict | Tutorials, throwaway demos | **Anything real** |

### Cross-AZ data transfer

Traffic between AZs costs about **$0.01/GB in each direction** (~$0.02/GB round trip). With a load balancer spraying traffic randomly across 3 AZs, ~2/3 of requests cross an AZ boundary.

- For chatty microservices this becomes a real bill.
- ALB has **cross-zone load balancing always on and free**.
- NLB has cross-zone **off by default** and **charges** when you turn it on.
- Consider **Availability Zone affinity / zonal shift** for very chatty internal traffic.

### Security group chaining (do this)

```
ALB SG        : inbound 443 from 0.0.0.0/0
App SG        : inbound 8080 from ALB SG          ← reference the SG, not an IP
Database SG   : inbound 5432 from App SG          ← reference the SG, not an IP
```

Because ASG instances get **new IP addresses every time they launch**, you can never use IP-based rules with an ASG. Referencing security groups is the only approach that survives scaling.

---

## 9. Saving Money: Spot, Mixed Instances, Warm Pools

### Purchase options

| Option | Discount | Risk | Use for |
|---|---|---|---|
| **On-Demand** | 0% (baseline) | None | Baseline capacity |
| **Reserved Instances / Savings Plans** | Up to ~72% | 1–3 year commitment | Predictable steady load |
| **Spot Instances** | Up to **90%** | ⚠️ **2-minute termination notice** | Fault-tolerant, stateless work |

### Mixed Instances Policy ⭐

The single best cost feature in ASGs. One ASG, multiple instance types, mixed purchase options.

```json
{
  "MixedInstancesPolicy": {
    "LaunchTemplate": {
      "LaunchTemplateSpecification": { "LaunchTemplateName": "tutorial-web-lt" },
      "Overrides": [
        { "InstanceType": "m6i.large" },
        { "InstanceType": "m6a.large" },
        { "InstanceType": "m5.large" },
        { "InstanceType": "m5a.large" },
        { "InstanceType": "m5n.large" }
      ]
    },
    "InstancesDistribution": {
      "OnDemandBaseCapacity": 2,
      "OnDemandPercentageAboveBaseCapacity": 25,
      "SpotAllocationStrategy": "price-capacity-optimized"
    }
  }
}
```

**Reading that in plain English:** "Always keep 2 On-Demand instances no matter what. Above those 2, make 25% On-Demand and 75% Spot. For the Spot instances, pick whichever of these 5 types is cheapest *and* least likely to be interrupted."

**✅ Pros:** 50–70% cost cut is typical. More instance types = deeper Spot capacity pools = fewer interruptions.
**❌ Cons:** Instance types must be genuinely interchangeable (similar CPU/RAM). Your app must tolerate sudden termination.

**Modern alternative — Attribute-Based Instance Selection:** instead of listing types, describe requirements ("4–8 vCPUs, 16+ GB RAM, no GPU") and AWS auto-selects matching types, including new ones released later. Less maintenance.

### Handling Spot interruptions gracefully

1. Enable **Capacity Rebalance** on the ASG — AWS proactively replaces instances that are *at elevated risk*, before the 2-minute notice.
2. Listen for the interruption notice in the instance metadata or via EventBridge.
3. On notice: stop accepting new work, finish current requests, deregister from the target group, save state.
4. Set the target group's **deregistration delay** (connection draining) to ~30–60 seconds.

**Never put on Spot:** databases, anything with local state you can't lose, single-instance services, or long jobs that can't checkpoint.

### Warm Pools

A **Warm Pool** keeps pre-initialized instances in `Stopped`, `Running`, or `Hibernated` state, ready to join in seconds instead of minutes.

**✅ Pros:** Boot time drops from ~5 minutes to ~30 seconds. `Stopped` instances cost nothing in compute — you only pay for their EBS volumes.
**❌ Cons:** Ongoing EBS storage cost; extra complexity; needs lifecycle hooks to work well.
**🎯 Best for:** Apps with long initialization (big JVM apps, huge container images, ML model loading).

---

## 10. Updating Your App Safely (Instance Refresh)

You changed your code. How do you roll it out to 50 running servers?

### The workflow

1. Bake a new AMI (or update your user data script)
2. Create a **new version** of the Launch Template
3. Point the ASG at the new version (or `$Latest`)
4. Start an **Instance Refresh**

```bash
aws autoscaling start-instance-refresh \
  --auto-scaling-group-name tutorial-asg \
  --preferences '{
      "MinHealthyPercentage": 90,
      "MaxHealthyPercentage": 110,
      "InstanceWarmup": 300,
      "CheckpointPercentages": [20, 50, 100],
      "CheckpointDelay": 600,
      "AutoRollback": true,
      "SkipMatching": true
    }'
```

**What each setting does:**

| Setting | Meaning |
|---|---|
| `MinHealthyPercentage: 90` | Never let more than 10% be out of service at once |
| `MaxHealthyPercentage: 110` | Allowed to temporarily overshoot by 10% — **launch new before terminating old** (safer, briefly costlier) |
| `InstanceWarmup` | Wait this long before counting a new instance as healthy |
| `CheckpointPercentages` | Pause at 20%, then 50%, then 100% — a **canary deployment** |
| `CheckpointDelay: 600` | Wait 10 minutes at each checkpoint so you can watch dashboards |
| `AutoRollback: true` | If a CloudWatch alarm fires, automatically revert to the old version |
| `SkipMatching: true` | Don't replace instances already on the new config |

### Deployment strategies compared

| Strategy | How | Pros | Cons |
|---|---|---|---|
| **Rolling (Instance Refresh)** | Replace a few at a time | Cheap, built-in, no extra infra | Two versions live at once; slow for big fleets |
| **Blue/Green** | Build a whole second ASG, switch the ALB, delete the old | Instant rollback, zero mixed versions | Doubles cost during the switch |
| **Canary** | Refresh with checkpoints at 10% first | Catches bad releases early with tiny blast radius | Slowest |
| **In-place patching** | SSH/SSM in and update running servers | Fast | ❌ **Anti-pattern.** Breaks immutability; new instances launch with old code. Don't. |

> 💡 **Golden rule:** ASG instances should be **immutable**. Never modify a running instance. Change the image, replace the instance. If you ever fix something by hand on a live ASG instance, that fix vanishes the moment the ASG replaces it — and it *will* replace it.

---

## 11. Alternatives to Auto Scaling Groups

ASGs are not always the right answer.

| Option | What it is | ✅ Pros | ❌ Cons | Choose when |
|---|---|---|---|---|
| **EC2 Auto Scaling Group** | Scales VMs | Full OS control, any software, mature, free | You patch the OS; slow boots (minutes); you manage AMIs | Legacy apps, custom kernels, GPU/HPC, licensed software |
| **AWS Lambda** | Run code, no servers | Scales instantly to thousands; pay per millisecond; zero ops | 15-min max runtime; cold starts; memory caps; hard to run big frameworks | Event-driven work, APIs, cron jobs, file processing |
| **AWS Fargate (ECS/EKS)** | Containers, no VMs to manage | No servers to patch; per-second billing; fast scaling | Costs more per unit of compute; less control; no GPU on some configs | Containerized apps where you want zero infrastructure work |
| **ECS on EC2** | Containers on your own EC2 (backed by an ASG) | Cheaper at scale; can use Spot; bin-packing efficiency | You manage the EC2 layer | Many containers, cost-sensitive |
| **EKS + Karpenter** | Kubernetes with a smart node provisioner | Launches exactly the right instance in ~60s; excellent Spot handling; often beats ASG | Kubernetes complexity; more to learn | You're already on Kubernetes |
| **AWS App Runner** | Give it a container or repo, get a URL | Dead simple; auto-scales to zero | Very limited configuration; fewer regions | Simple web services and APIs |
| **Elastic Beanstalk** | PaaS that builds ASGs for you | Fast to start; uses ASGs underneath | Abstraction leaks; feels dated | Quick deploys where you don't want to learn the plumbing |
| **AWS Auto Scaling (application)** | Scales DynamoDB, ECS, Aurora, SageMaker | Same scaling logic for non-EC2 resources | Not for EC2 | Scaling databases and managed services |

### Quick decision flow

```
Is your workload short, event-driven, under 15 minutes?
   └─ YES → Lambda

Is it containerized?
   ├─ Want zero infrastructure work?      → Fargate
   ├─ Already using Kubernetes?           → EKS + Karpenter
   └─ Cost-sensitive at large scale?      → ECS on EC2 (with an ASG)

Do you need full OS control, GPUs, or special licensing?
   └─ YES → EC2 Auto Scaling Group

Is it a database or managed AWS service?
   └─ YES → Application Auto Scaling
```

---

## 12. Pros and Cons of ASGs Overall

### ✅ Pros

| Advantage | Detail |
|---|---|
| **Free service** | Zero charge for the ASG itself |
| **True self-healing** | Failed instances replaced automatically, 24/7 |
| **Multi-AZ resilience** | Survives an entire data center outage |
| **Elastic cost** | Pay only for capacity you're using |
| **Mature and battle-tested** | Launched 2009; runs a huge share of the internet |
| **Deep integration** | ALB/NLB, CloudWatch, EventBridge, SNS, Systems Manager, CodeDeploy |
| **Total control** | Any OS, any kernel module, any agent, GPUs, bare-metal |
| **Great Spot support** | Mixed instances policies deliver 50–90% savings |
| **Safe deployments** | Instance Refresh with checkpoints and auto-rollback |

### ❌ Cons

| Disadvantage | Detail | Mitigation |
|---|---|---|
| **Slow scaling** | Instances take 1–5 min to become useful | Warm pools; pre-baked AMIs; predictive scaling |
| **Minimum granularity is a whole VM** | Can't add "half a server" | Containers or Lambda |
| **You own the OS** | Patching, hardening, agents, CVEs | Golden AMI pipeline (EC2 Image Builder); SSM Patch Manager |
| **AMI management overhead** | Every change needs a new image | Automated image pipelines |
| **Stateless-only** | Local disk vanishes when an instance dies | Store state in RDS/DynamoDB/S3/EFS/ElastiCache |
| **Reacts, doesn't predict** | Sudden spikes get served slowly | Predictive + scheduled scaling |
| **Config sprawl** | Launch templates, versions, policies, hooks pile up | Terraform / CloudFormation / CDK — never click-ops in production |
| **Can't scale to zero cheaply** | Min of 0 works, but cold start is painful | Lambda or Fargate for spiky low-volume work |
| **Bill can run away** | Misconfigured max = surprise invoice | Set a sane max; AWS Budgets alerts |

---

## 13. Troubleshooting Guide

### Problem: Instances launch, then terminate, then launch again (launch loop) 🔁

**The single most common ASG problem.** The ASG launches an instance, a health check fails, it terminates it, and repeats forever — burning money.

**Diagnose:** ASG → **Activity** tab. Read the status reason.

| Cause | Fix |
|---|---|
| Health check grace period too short | Raise to 300–600s; measure real boot time first |
| App isn't actually starting | SSM into an instance: `sudo systemctl status nginx`, `sudo cat /var/log/cloud-init-output.log` |
| Health check path wrong | Confirm `/health` returns HTTP 200: `curl -i localhost/health` |
| Security group blocks the ALB | App SG must allow the ALB SG on the app port |
| User data script failing | Check `/var/log/cloud-init-output.log` — this file is where the truth lives |
| Wrong health check port | Target group port must match where the app actually listens |

---

### Problem: `Launch failed: not enough free addresses in subnet`

Subnet is out of IPs. See the [subnet math](#subnet-capacity-math-the-silent-scaling-ceiling) section. Add subnets in more AZs, or build bigger ones (subnets can't be resized).

---

### Problem: `InsufficientInstanceCapacity`

AWS is out of that instance type in that AZ right now.

**Fixes:** add more AZs to the ASG; use a **Mixed Instances Policy** with 5–10 types; try a different instance family; use **Capacity Reservations** for guaranteed capacity; use attribute-based selection.

---

### Problem: Spot instances constantly interrupted

**Fixes:** add many more instance types (10+); use `price-capacity-optimized` allocation strategy; enable **Capacity Rebalance**; keep a meaningful On-Demand base; spread across all AZs.

---

### Problem: ASG isn't scaling out even though CPU is high

**Checklist:**
1. Is `desired` already at `max`? (Most common answer.)
2. Is the CloudWatch alarm actually in `ALARM` state?
3. Is a cooldown or warmup still active?
4. Are scaling **processes suspended**? Check ASG → **Advanced configuration** → Suspended Processes. `Launch`, `Terminate`, `AZRebalance`, `HealthCheck` can all be paused — sometimes left suspended by a past deploy.
5. Is the alarm watching the right metric with enough datapoints?
6. Have you hit your **account EC2 vCPU service quota**? Check Service Quotas.

---

### Problem: ASG isn't scaling in

1. Is `desired` already at `min`?
2. **Scale-in protection** enabled on instances?
3. Is the `ScaleIn` process suspended?
4. Target tracking refuses to scale in if it would push the metric above target — this is by design.
5. A **lifecycle hook** may be stuck in `Terminating:Wait` — check for a hook that never gets a `CONTINUE` signal (it will sit there until the heartbeat timeout, up to 48 hours).

---

### Problem: Constant flapping (scale out, scale in, repeat) 📈📉

**Fixes:** widen the gap between scale-out and scale-in thresholds; increase cooldown/warmup; require more consecutive datapoints before the alarm fires; switch to target tracking (it has built-in damping); make sure your instance warmup exceeds real boot time.

---

### Problem: Users get errors during scale-in

Instances are terminated while still serving requests.

**Fixes:**
1. Set target group **deregistration delay** (connection draining) to 30–120 seconds.
2. Add a **lifecycle hook** on `Terminating` to run graceful shutdown.
3. Make your app handle `SIGTERM`: stop accepting new work, finish in-flight requests, exit.

---

### Problem: New code isn't on new instances

You edited a running server by hand. That change is not in the AMI or user data. **Fix:** update the launch template / AMI and run an Instance Refresh. Never patch live instances.

---

### Where to look for logs

| Log | Location | Tells you |
|---|---|---|
| ASG Activity History | Console → ASG → Activity tab | Why an instance launched or terminated |
| User data output | `/var/log/cloud-init-output.log` | Why your startup script failed |
| System boot | `/var/log/messages`, `journalctl -xe` | OS-level problems |
| ALB access logs | S3 (must be enabled) | Per-request status codes |
| CloudTrail | Console → CloudTrail | Who changed the ASG config |
| EC2 Serial Console / Screenshot | EC2 → Instance → Monitor and troubleshoot | Boot failures with no SSH |

---

## 14. Gotchas That Bite Everyone

1. **Desired capacity gets overwritten by your IaC.** Terraform/CloudFormation will reset `desired_capacity` to whatever's in code on the next apply, undoing all scaling. **Fix:** use `ignore_changes = [desired_capacity]` in Terraform.

2. **`$Latest` vs. `$Default` launch template version.** Using `$Latest` means every template edit affects new launches immediately — including your half-finished experiment. Pin an explicit version number in production.

3. **A Launch Template with a subnet baked in.** If the template specifies a subnet, it fights the ASG's multi-AZ logic. Leave subnet out of the template.

4. **Min = Max.** The ASG can never scale. Surprisingly common in copy-pasted configs.

5. **Terminating an instance manually doesn't reduce desired capacity.** The ASG immediately replaces it. To actually shrink, change desired capacity.

6. **Suspended processes are invisible.** If `Launch` is suspended, your ASG silently does nothing forever. Nothing errors. Check this tab when confused.

7. **AZ rebalancing terminates healthy instances.** If AZs get uneven, the ASG proactively launches in the empty AZ and terminates in the crowded one — even during peak traffic. Normal, but startling.

8. **Health check grace period is per-instance, from launch — not from when it becomes healthy.** Slow boots get killed.

9. **AZs have different names in different accounts.** `us-east-1a` in your account may be a different physical building than `us-east-1a` in mine. Use **AZ IDs** (`use1-az1`) when it matters.

10. **Deleting an ASG terminates all its instances.** Immediately. No confirmation beyond the dialog.

11. **Target tracking needs a metric that falls when instances rise.** Using raw request count or queue *arrival rate* pins you at max capacity. Use per-target metrics.

12. **Lifecycle hooks default to a 1-hour heartbeat and can be extended to 48 hours.** A hook whose Lambda never sends `CONTINUE` will stall your entire deployment silently.

13. **Detailed monitoring costs money but is usually worth it.** Default metrics arrive every 5 minutes; detailed every 1 minute. With 5-minute metrics, your ASG reacts up to 5 minutes late.

14. **Scale-in protection doesn't protect against health-check replacement.** It only stops scale-in events. Unhealthy instances still get terminated.

15. **The ALB is not free.** ~$16/month plus LCU charges even at zero traffic.

16. **Warm pool instances still cost EBS.** Stopped instances = no compute charge, but the disks still bill.

17. **Instance Refresh doesn't roll back on its own unless `AutoRollback: true` and CloudWatch alarms are specified.** Set both.

18. **Capacity Rebalance + a slow app = churn.** If your app takes 6 minutes to warm up and Spot rebalancing keeps swapping instances, you may never reach steady state. Tune warmup, or use more On-Demand.

---

## 15. Best Practices Checklist

**Reliability**
- [ ] Span **at least 3 Availability Zones**
- [ ] Enable **ELB health checks**, not just EC2
- [ ] Use a lightweight, dedicated `/health` endpoint
- [ ] Set health check grace period to ~2x measured boot time
- [ ] Min size ≥ 2 (never a single point of failure)
- [ ] Set max size high enough for real spikes but low enough to cap the bill

**Networking**
- [ ] App instances in **private** subnets
- [ ] Size subnets generously (`/22` or larger for app tiers)
- [ ] **Security group chaining** — never IP-based rules
- [ ] One NAT Gateway per AZ (production)
- [ ] Free **Gateway VPC Endpoints** for S3 and DynamoDB
- [ ] Interface endpoints for SSM, ECR, CloudWatch if traffic is heavy

**Scaling**
- [ ] Start with **target tracking** on `ALBRequestCountPerTarget` or CPU
- [ ] Add **scheduled** or **predictive** scaling for known patterns
- [ ] Enable **detailed monitoring** (1-minute metrics)
- [ ] Instance warmup ≥ real time-to-serve-traffic
- [ ] Scale out aggressively, scale in conservatively

**Cost**
- [ ] **Mixed Instances Policy** with 5–10 instance types
- [ ] Spot for the flexible portion, On-Demand base for the floor
- [ ] `price-capacity-optimized` allocation strategy
- [ ] **Capacity Rebalance** on
- [ ] Savings Plans for the steady baseline
- [ ] Scheduled scale-to-zero for dev/test at night
- [ ] AWS Budgets alert on the account

**Operations**
- [ ] Everything in **Terraform / CloudFormation / CDK** — no click-ops
- [ ] **Immutable infrastructure** — never patch live instances
- [ ] Golden AMI pipeline (EC2 Image Builder)
- [ ] **Instance Refresh** with checkpoints and `AutoRollback`
- [ ] Lifecycle hooks for graceful start and shutdown
- [ ] IMDSv2 required (`HttpTokens: required`)
- [ ] Instance profile with least-privilege IAM, **never hardcoded keys**
- [ ] Tag everything (owner, environment, cost center)
- [ ] SNS notifications on launch/terminate failures
- [ ] Ship logs off-instance (CloudWatch Logs) — local disks are ephemeral
- [ ] `ignore_changes` on `desired_capacity` in Terraform

---

## 16. Cleanup (Don't Skip This)

Delete in this order or you'll get dependency errors:

1. **Auto Scaling Group** → EC2 → Auto Scaling Groups → select `tutorial-asg` → Actions → **Delete** (this terminates all instances)
2. Wait until all instances show **Terminated**
3. **Load Balancer** → select `tutorial-alb` → Actions → **Delete**
4. **Target Group** → select `tutorial-tg` → Actions → **Delete**
5. **Launch Template** → select `tutorial-web-lt` → Actions → **Delete**
6. **Security Groups** → delete `tutorial-app-sg` **first**, then `tutorial-alb-sg` (app SG references the ALB SG)
7. **CloudWatch Alarms** → delete any alarms starting with `TargetTracking-tutorial-asg`

Then check **Billing → Cost Explorer** the next day to confirm nothing is still running.

---

## 17. Cheat Sheet

### Essential CLI commands

```bash
# See your ASG's current state
aws autoscaling describe-auto-scaling-groups \
  --auto-scaling-group-names tutorial-asg

# Read the activity log (the #1 troubleshooting command)
aws autoscaling describe-scaling-activities \
  --auto-scaling-group-name tutorial-asg --max-items 20

# Manually set capacity
aws autoscaling set-desired-capacity \
  --auto-scaling-group-name tutorial-asg --desired-capacity 5

# Change min/max
aws autoscaling update-auto-scaling-group \
  --auto-scaling-group-name tutorial-asg --min-size 3 --max-size 20

# Pull an instance out for debugging (ASG won't replace it)
aws autoscaling enter-standby \
  --instance-ids i-0abc123 \
  --auto-scaling-group-name tutorial-asg \
  --should-decrement-desired-capacity
# ...and put it back
aws autoscaling exit-standby --instance-ids i-0abc123

# Roll out a new launch template version
aws autoscaling start-instance-refresh \
  --auto-scaling-group-name tutorial-asg

# Check refresh progress
aws autoscaling describe-instance-refreshes \
  --auto-scaling-group-name tutorial-asg

# Emergency: cancel a bad rollout
aws autoscaling rollback-instance-refresh \
  --auto-scaling-group-name tutorial-asg

# See what's suspended (the hidden gotcha)
aws autoscaling describe-auto-scaling-groups \
  --auto-scaling-group-names tutorial-asg \
  --query 'AutoScalingGroups[0].SuspendedProcesses'
```

### Key numbers to remember

| Thing | Value |
|---|---|
| IPs AWS reserves per subnet | **5** |
| Minimum subnet size | `/28` (11 usable) |
| Spot termination warning | **2 minutes** |
| Default health check grace | 300 seconds |
| Default cooldown | 300 seconds |
| Predictive scaling data needed | 24 hours minimum, 14 days ideal |
| Lifecycle hook max heartbeat | 48 hours |
| Default ASG limit per Region | 200 (raisable) |
| ASG service cost | **$0** |

### One-paragraph summary

An **Auto Scaling Group** watches a fleet of identical EC2 instances defined by a **Launch Template**, spread across multiple **Availability Zones** inside your **VPC**, sitting behind a **Load Balancer**. It keeps the count between your **min** and **max**, replaces anything that fails a **health check**, and adjusts the **desired capacity** based on **scaling policies** driven by **CloudWatch** metrics. Put instances in **private subnets**, chain your **security groups**, use **target tracking** as your default policy, add **mixed instances with Spot** to cut costs, deploy via **Instance Refresh** with auto-rollback, and never, ever fix a problem by logging into a live instance.

---

*Last updated: July 2026. AWS console layouts change frequently — the concepts here are stable, but button locations may shift slightly.*
