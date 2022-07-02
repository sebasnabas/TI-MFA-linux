#!/usr/bin/env bash

pushd "$(dirname "${BASH_SOURCE[0]}")" || exit 1

vagrant up

vagrant ssh -c 'sudo /vagrant/mininet_topo1.py'

tools_dir='../../../tools'
iperf_results_dir='iperf3_results'
processed_results_dir='processed_iperf3_results'

${tools_dir}/iperf_preprocessor.sh ${iperf_results_dir}/0_link_failures.json ${processed_results_dir} \
    && mv ${processed_results_dir}/results/1.dat ${processed_results_dir}/0_link_failures.dat

${tools_dir}/iperf_preprocessor.sh ${iperf_results_dir}/1_link_failures.json ${processed_results_dir} \
    && mv ${processed_results_dir}/results/1.dat ${processed_results_dir}/1_link_failure.dat

${tools_dir}/iperf_preprocessor.sh ${iperf_results_dir}/2_link_failures.json ${processed_results_dir} \
    && mv ${processed_results_dir}/results/1.dat ${processed_results_dir}/2_link_failures.dat

${tools_dir}/iperf_plot.sh ${processed_results_dir} topo_1_extra_node_mininet

vagrant destroy -f
