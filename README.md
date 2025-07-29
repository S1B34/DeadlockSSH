🍯 DeadlockSSH: The Goofiest SSH Honeypot on the Block

Ever wondered what script kiddies and bots are up to? Do you have a burning desire to watch them fumble around in a digital sandbox you control? Well, my friend, you've stumbled upon the perfect project!

DeadlockSSH is the digital equivalent of a venus flytrap for nosy hackers. It looks like a real SSH server, it smells like a real SSH server, but it's actually a cleverly disguised trap that will log their every move while leaving them stuck in connection limbo. It's like a roach motel for the internet's uninvited guests: they check in, but they don't check out (or get a shell).

What's in the Box? (aka Features)

This isn't your grandma's honeypot. We've packed it with all sorts of goodies:

•
Port Flexibility: Run it on the classic port 22, or go wild and pick 2222, 22222, or even 8008! The world is your oyster.

•
Juggles Connections: Thanks to the magic of multi-threading, it can handle a whole crowd of unwanted visitors at once.

•
Slow-Mo Banner: We send the SSH banner one... character... at... a... time. Why? Because it's hilarious and it mimics some real-world servers. Patience is a virtue, attackers!

•
The Annoyance-O-Meter™: The more an IP address connects, the longer they have to wait. It's our special way of saying, "Maybe find a new hobby?"

•
Super-Sleuth Logging: We write down everything. Timestamps, IPs, what they tried to send us... it's all going in the logbook. We'll even rotate the logs so your hard drive doesn't cry for mercy.

•
Pulls a Houdini: Shuts down gracefully with a simple Ctrl+C. No mess, no fuss.

•
Bonus! HTTP Stats Party: Flip a switch, and you get a little web server showing off your honeypot's stats. See who's been knocking on your door the most!

Getting Your Hands Dirty (Installation)

Guess what? You probably already have everything you need. If you've got Python 3.6+ installed, you're golden. No crazy dependencies, no weird installations.

Bash


# Just clone or download the files. That's it. Seriously.
git clone [your-repo-link-here]
cd [your-repo-folder]


Let's Light This Candle! (Quick Start)

Ready to start catching some flies?

Bash


# Fire it up with the default settings (it'll listen on port 2222)
python3 honeypot.py

# Feeling brave? Run it on the actual SSH port (you'll need sudo for this!)
# Warning: Make sure your real SSH server isn't on this port!
sudo python3 honeypot.py -p 22

# Want to use your own custom settings? Easy peasy.
python3 honeypot.py -c config.ini


We've even included a config.ini file for you to tinker with. Go on, don't be shy!

The Nitty-Gritty (Configuration)

You can tweak almost everything in the config.ini file. Here's the cheat sheet:

OptionWhat it DoesMy Goofy AdviceportThe TCP port to listen on.Pick a weird one to confuse people.max_connectionsHow many connections it can juggle at once.Set it high and watch the world burn (or just connect).ssh_bannerThe fake SSH banner it shows.Make it say something funny like "All your base are belong to us".banner_delayHow slow the banner appears.Crank it up for maximum annoyance.initial_delayThe starting wait time for new visitors.A little patience-building exercise.delay_incrementHow much extra waiting time for repeat offenders."You get a second, and YOU get a second!"max_delayThe absolute longest they'll have to wait.Even we have our limits. 60 seconds is an eternity.log_fileWhere the juicy logs are stored.Name it totally_not_secret_stuff.log.enable_http_statsTurn on the stats web page.Do it! It's like a scoreboard for your honeypot.http_stats_portThe port for the stats page.8080 is a classic.

The Hall of Shame (HTTP Stats)

If you enabled the stats server, you can peek at who's been visiting. Just open your browser or use curl:

Bash


curl http://localhost:8080/stats


You'll get a lovely JSON trophy showing your total connections, who's active, and a leaderboard of your most persistent "fans".

A Word from Our Lawyers (Just Kidding, It's Me)

•
Play Nice: Only run this on networks you own. Don't be a jerk.

•
Check Local Laws: Make sure you're not breaking any rules. Boring, but important.

•
Privacy, Shmivacy? You're logging IPs. Be aware of that. This is for defense, not for snooping on your neighbor's cat videos.

Pimp My Honeypot (Contributing)

Got a wacky idea? Want to make it even goofier? We're all ears! Fork it, branch it, send a pull request. Let's make the internet a slightly more confusing place for attackers, together.





Disclaimer: DeadlockSSH is not responsible for any hackers who die of boredom while waiting for a shell prompt. Use responsibly.

