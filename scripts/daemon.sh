# !/bin/bash
pid = $$
(sleep 2 && kill $$) | sudo /home/anna/hyenae-0.36-1/src/hyenaed -I 1 -a 10.0.0.1 -u 10000
