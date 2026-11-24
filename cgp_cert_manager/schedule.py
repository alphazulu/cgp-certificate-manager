"""Apply explicitly saved timer configuration; never enable the timer."""
import os
import subprocess
import tempfile
from pathlib import Path
from .core import CONFIG, load

DROPIN=Path('/etc/systemd/system/cgp-letsencrypt.timer.d/90-cgp-manager.conf')

def render(schedule):
    hour=schedule.get('hour',3)
    delay=schedule.get('random_delay',900)
    if type(hour) is not int or not 0<=hour<=23 or type(delay) is not int or not 0<=delay<=3600:
        raise ValueError('Invalid renewal schedule')
    hours=sorted((hour,(hour+12)%24))
    return '[Timer]\nOnCalendar=\nOnCalendar=*-*-* %02d,%02d:00:00\nRandomizedDelaySec=%d\n'%(*hours,delay)

def apply():
    cfg=load(CONFIG)
    if 'schedule' not in cfg: return
    data=render(cfg['schedule'])
    DROPIN.parent.mkdir(parents=True,exist_ok=True)
    fd,tmp=tempfile.mkstemp(dir=DROPIN.parent)
    try:
        with os.fdopen(fd,'w') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp,0o644)
        os.replace(tmp,DROPIN)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)
    subprocess.run(['systemctl','daemon-reload'],check=True)
    if subprocess.run(['systemctl','is-active','--quiet','cgp-letsencrypt.timer']).returncode==0:
        subprocess.run(['systemctl','restart','cgp-letsencrypt.timer'],check=True)
