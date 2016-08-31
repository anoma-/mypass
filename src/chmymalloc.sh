#! /usr/bin/env bash

num=$1
sed -i "/if/ s/i == ./i == $num/" mymalloc.c
