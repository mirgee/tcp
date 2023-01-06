#!/bin/bash
nc 10.0.0.2 443
tshark -i utun4
