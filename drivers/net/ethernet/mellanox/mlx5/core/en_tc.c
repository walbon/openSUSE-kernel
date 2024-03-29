/*
 * Copyright (c) 2016, Mellanox Technologies. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <net/flow_dissector.h>
#include <net/sch_generic.h>
#include <net/pkt_cls.h>
#include <net/tc_act/tc_gact.h>
#include <net/tc_act/tc_skbedit.h>
#include <linux/mlx5/fs.h>
#include <linux/mlx5/device.h>
#include <linux/rhashtable.h>
#include <net/switchdev.h>
#include <net/tc_act/tc_mirred.h>
#include <net/tc_act/tc_vlan.h>
#include "en.h"
#include "en_tc.h"
#include "eswitch.h"

enum {
	MLX5E_TC_FLOW_ESWITCH	= BIT(0),
};

struct mlx5e_tc_flow {
	struct rhash_head	node;
	u64			cookie;
	u8			flags;
	struct mlx5_flow_handle *rule;
	struct mlx5_esw_flow_attr *attr;
};

#define MLX5E_TC_TABLE_NUM_ENTRIES 1024
#define MLX5E_TC_TABLE_NUM_GROUPS 4

static struct mlx5_flow_handle *
mlx5e_tc_add_nic_flow(struct mlx5e_priv *priv,
		      struct mlx5_flow_spec *spec,
		      u32 action, u32 flow_tag)
{
	struct mlx5_core_dev *dev = priv->mdev;
	struct mlx5_flow_destination dest = { 0 };
	struct mlx5_flow_act flow_act = {
		.action = action,
		.flow_tag = flow_tag,
		.encap_id = 0,
	};
	struct mlx5_fc *counter = NULL;
	struct mlx5_flow_handle *rule;
	bool table_created = false;

	if (action & MLX5_FLOW_CONTEXT_ACTION_FWD_DEST) {
		dest.type = MLX5_FLOW_DESTINATION_TYPE_FLOW_TABLE;
		dest.ft = priv->fs.vlan.ft.t;
	} else if (action & MLX5_FLOW_CONTEXT_ACTION_COUNT) {
		counter = mlx5_fc_create(dev, true);
		if (IS_ERR(counter))
			return ERR_CAST(counter);

		dest.type = MLX5_FLOW_DESTINATION_TYPE_COUNTER;
		dest.counter = counter;
	}

	if (IS_ERR_OR_NULL(priv->fs.tc.t)) {
		priv->fs.tc.t =
			mlx5_create_auto_grouped_flow_table(priv->fs.ns,
							    MLX5E_TC_PRIO,
							    MLX5E_TC_TABLE_NUM_ENTRIES,
							    MLX5E_TC_TABLE_NUM_GROUPS,
							    0, 0);
		if (IS_ERR(priv->fs.tc.t)) {
			netdev_err(priv->netdev,
				   "Failed to create tc offload table\n");
			rule = ERR_CAST(priv->fs.tc.t);
			goto err_create_ft;
		}

		table_created = true;
	}

	spec->match_criteria_enable = MLX5_MATCH_OUTER_HEADERS;
	rule = mlx5_add_flow_rules(priv->fs.tc.t, spec, &flow_act, &dest, 1);

	if (IS_ERR(rule))
		goto err_add_rule;

	return rule;

err_add_rule:
	if (table_created) {
		mlx5_destroy_flow_table(priv->fs.tc.t);
		priv->fs.tc.t = NULL;
	}
err_create_ft:
	mlx5_fc_destroy(dev, counter);

	return rule;
}

static void mlx5e_tc_del_nic_flow(struct mlx5e_priv *priv,
				  struct mlx5e_tc_flow *flow)
{
	struct mlx5_fc *counter = NULL;

	if (!IS_ERR(flow->rule)) {
		counter = mlx5_flow_rule_counter(flow->rule);
		mlx5_del_flow_rules(flow->rule);
		mlx5_fc_destroy(priv->mdev, counter);
	}

	if (!mlx5e_tc_num_filters(priv) && (priv->fs.tc.t)) {
		mlx5_destroy_flow_table(priv->fs.tc.t);
		priv->fs.tc.t = NULL;
	}
}

static struct mlx5_flow_handle *
mlx5e_tc_add_fdb_flow(struct mlx5e_priv *priv,
		      struct mlx5_flow_spec *spec,
		      struct mlx5_esw_flow_attr *attr)
{
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	int err;

	err = mlx5_eswitch_add_vlan_action(esw, attr);
	if (err)
		return ERR_PTR(err);

	return mlx5_eswitch_add_offloaded_rule(esw, spec, attr);
}

static void mlx5e_tc_del_fdb_flow(struct mlx5e_priv *priv,
				  struct mlx5e_tc_flow *flow)
{
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;

	mlx5_eswitch_del_offloaded_rule(esw, flow->rule, flow->attr);

	mlx5_eswitch_del_vlan_action(esw, flow->attr);
}

/* we get here also when setting rule to the FW failed, etc. It means that the
 * flow rule itself might not exist, but some offloading related to the actions
 * should be cleaned.
 */
static void mlx5e_tc_del_flow(struct mlx5e_priv *priv,
			      struct mlx5e_tc_flow *flow)
{
	if (flow->flags & MLX5E_TC_FLOW_ESWITCH)
		mlx5e_tc_del_fdb_flow(priv, flow);
	else
		mlx5e_tc_del_nic_flow(priv, flow);
}

static int __parse_cls_flower(struct mlx5e_priv *priv,
			      struct mlx5_flow_spec *spec,
			      struct tc_cls_flower_offload *f,
			      u8 *min_inline)
{
	void *headers_c = MLX5_ADDR_OF(fte_match_param, spec->match_criteria,
				       outer_headers);
	void *headers_v = MLX5_ADDR_OF(fte_match_param, spec->match_value,
				       outer_headers);
	u16 addr_type = 0;
	u8 ip_proto = 0;

	*min_inline = MLX5_INLINE_MODE_L2;

	if (f->dissector->used_keys &
	    ~(BIT(FLOW_DISSECTOR_KEY_CONTROL) |
	      BIT(FLOW_DISSECTOR_KEY_BASIC) |
	      BIT(FLOW_DISSECTOR_KEY_ETH_ADDRS) |
	      BIT(FLOW_DISSECTOR_KEY_VLAN) |
	      BIT(FLOW_DISSECTOR_KEY_IPV4_ADDRS) |
	      BIT(FLOW_DISSECTOR_KEY_IPV6_ADDRS) |
	      BIT(FLOW_DISSECTOR_KEY_PORTS))) {
		netdev_warn(priv->netdev, "Unsupported key used: 0x%x\n",
			    f->dissector->used_keys);
		return -EOPNOTSUPP;
	}

	if (dissector_uses_key(f->dissector, FLOW_DISSECTOR_KEY_CONTROL)) {
		struct flow_dissector_key_control *key =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_CONTROL,
						  f->key);

		struct flow_dissector_key_control *mask =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_CONTROL,
						  f->mask);
		addr_type = key->addr_type;

		if (mask->flags & FLOW_DIS_IS_FRAGMENT) {
			MLX5_SET(fte_match_set_lyr_2_4, headers_c, frag, 1);
			MLX5_SET(fte_match_set_lyr_2_4, headers_v, frag,
				 key->flags & FLOW_DIS_IS_FRAGMENT);

			/* the HW doesn't need L3 inline to match on frag=no */
			if (key->flags & FLOW_DIS_IS_FRAGMENT)
				*min_inline = MLX5_INLINE_MODE_IP;
		}
	}

	if (dissector_uses_key(f->dissector, FLOW_DISSECTOR_KEY_BASIC)) {
		struct flow_dissector_key_basic *key =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_BASIC,
						  f->key);
		struct flow_dissector_key_basic *mask =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_BASIC,
						  f->mask);
		ip_proto = key->ip_proto;

		MLX5_SET(fte_match_set_lyr_2_4, headers_c, ethertype,
			 ntohs(mask->n_proto));
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, ethertype,
			 ntohs(key->n_proto));

		MLX5_SET(fte_match_set_lyr_2_4, headers_c, ip_protocol,
			 mask->ip_proto);
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, ip_protocol,
			 key->ip_proto);

		if (mask->ip_proto)
			*min_inline = MLX5_INLINE_MODE_IP;
	}

	if (dissector_uses_key(f->dissector, FLOW_DISSECTOR_KEY_ETH_ADDRS)) {
		struct flow_dissector_key_eth_addrs *key =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_ETH_ADDRS,
						  f->key);
		struct flow_dissector_key_eth_addrs *mask =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_ETH_ADDRS,
						  f->mask);

		ether_addr_copy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_c,
					     dmac_47_16),
				mask->dst);
		ether_addr_copy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v,
					     dmac_47_16),
				key->dst);

		ether_addr_copy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_c,
					     smac_47_16),
				mask->src);
		ether_addr_copy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v,
					     smac_47_16),
				key->src);
	}

	if (dissector_uses_key(f->dissector, FLOW_DISSECTOR_KEY_VLAN)) {
		struct flow_dissector_key_vlan *key =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_VLAN,
						  f->key);
		struct flow_dissector_key_vlan *mask =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_VLAN,
						  f->mask);
		if (mask->vlan_id || mask->vlan_priority) {
			MLX5_SET(fte_match_set_lyr_2_4, headers_c, cvlan_tag, 1);
			MLX5_SET(fte_match_set_lyr_2_4, headers_v, cvlan_tag, 1);

			MLX5_SET(fte_match_set_lyr_2_4, headers_c, first_vid, mask->vlan_id);
			MLX5_SET(fte_match_set_lyr_2_4, headers_v, first_vid, key->vlan_id);

			MLX5_SET(fte_match_set_lyr_2_4, headers_c, first_prio, mask->vlan_priority);
			MLX5_SET(fte_match_set_lyr_2_4, headers_v, first_prio, key->vlan_priority);
		}
	}

	if (addr_type == FLOW_DISSECTOR_KEY_IPV4_ADDRS) {
		struct flow_dissector_key_ipv4_addrs *key =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_IPV4_ADDRS,
						  f->key);
		struct flow_dissector_key_ipv4_addrs *mask =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_IPV4_ADDRS,
						  f->mask);

		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_c,
				    src_ipv4_src_ipv6.ipv4_layout.ipv4),
		       &mask->src, sizeof(mask->src));
		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v,
				    src_ipv4_src_ipv6.ipv4_layout.ipv4),
		       &key->src, sizeof(key->src));
		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_c,
				    dst_ipv4_dst_ipv6.ipv4_layout.ipv4),
		       &mask->dst, sizeof(mask->dst));
		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v,
				    dst_ipv4_dst_ipv6.ipv4_layout.ipv4),
		       &key->dst, sizeof(key->dst));

		if (mask->src || mask->dst)
			*min_inline = MLX5_INLINE_MODE_IP;
	}

	if (addr_type == FLOW_DISSECTOR_KEY_IPV6_ADDRS) {
		struct flow_dissector_key_ipv6_addrs *key =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_IPV6_ADDRS,
						  f->key);
		struct flow_dissector_key_ipv6_addrs *mask =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_IPV6_ADDRS,
						  f->mask);

		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_c,
				    src_ipv4_src_ipv6.ipv6_layout.ipv6),
		       &mask->src, sizeof(mask->src));
		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v,
				    src_ipv4_src_ipv6.ipv6_layout.ipv6),
		       &key->src, sizeof(key->src));

		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_c,
				    dst_ipv4_dst_ipv6.ipv6_layout.ipv6),
		       &mask->dst, sizeof(mask->dst));
		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v,
				    dst_ipv4_dst_ipv6.ipv6_layout.ipv6),
		       &key->dst, sizeof(key->dst));

		if (ipv6_addr_type(&mask->src) != IPV6_ADDR_ANY ||
		    ipv6_addr_type(&mask->dst) != IPV6_ADDR_ANY)
			*min_inline = MLX5_INLINE_MODE_IP;
	}

	if (dissector_uses_key(f->dissector, FLOW_DISSECTOR_KEY_PORTS)) {
		struct flow_dissector_key_ports *key =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_PORTS,
						  f->key);
		struct flow_dissector_key_ports *mask =
			skb_flow_dissector_target(f->dissector,
						  FLOW_DISSECTOR_KEY_PORTS,
						  f->mask);
		switch (ip_proto) {
		case IPPROTO_TCP:
			MLX5_SET(fte_match_set_lyr_2_4, headers_c,
				 tcp_sport, ntohs(mask->src));
			MLX5_SET(fte_match_set_lyr_2_4, headers_v,
				 tcp_sport, ntohs(key->src));

			MLX5_SET(fte_match_set_lyr_2_4, headers_c,
				 tcp_dport, ntohs(mask->dst));
			MLX5_SET(fte_match_set_lyr_2_4, headers_v,
				 tcp_dport, ntohs(key->dst));
			break;

		case IPPROTO_UDP:
			MLX5_SET(fte_match_set_lyr_2_4, headers_c,
				 udp_sport, ntohs(mask->src));
			MLX5_SET(fte_match_set_lyr_2_4, headers_v,
				 udp_sport, ntohs(key->src));

			MLX5_SET(fte_match_set_lyr_2_4, headers_c,
				 udp_dport, ntohs(mask->dst));
			MLX5_SET(fte_match_set_lyr_2_4, headers_v,
				 udp_dport, ntohs(key->dst));
			break;
		default:
			netdev_err(priv->netdev,
				   "Only UDP and TCP transport are supported\n");
			return -EINVAL;
		}

		if (mask->src || mask->dst)
			*min_inline = MLX5_INLINE_MODE_TCP_UDP;
	}

	return 0;
}

static int parse_cls_flower(struct mlx5e_priv *priv,
			    struct mlx5e_tc_flow *flow,
			    struct mlx5_flow_spec *spec,
			    struct tc_cls_flower_offload *f)
{
	struct mlx5_core_dev *dev = priv->mdev;
	struct mlx5_eswitch *esw = dev->priv.eswitch;
	struct mlx5_eswitch_rep *rep = priv->ppriv;
	u8 min_inline;
	int err;

	err = __parse_cls_flower(priv, spec, f, &min_inline);

	if (!err && (flow->flags & MLX5E_TC_FLOW_ESWITCH) &&
	    rep->vport != FDB_UPLINK_VPORT) {
		if (esw->offloads.inline_mode != MLX5_INLINE_MODE_NONE &&
		    esw->offloads.inline_mode < min_inline) {
			netdev_warn(priv->netdev,
				    "Flow is not offloaded due to min inline setting, required %d actual %d\n",
				    min_inline, esw->offloads.inline_mode);
			return -EOPNOTSUPP;
		}
	}

	return err;
}

static int parse_tc_nic_actions(struct mlx5e_priv *priv, struct tcf_exts *exts,
				u32 *action, u32 *flow_tag)
{
	const struct tc_action *a;

	if (tc_no_actions(exts))
		return -EINVAL;

	*flow_tag = MLX5_FS_DEFAULT_FLOW_TAG;
	*action = 0;

	tc_for_each_action(a, exts) {
		/* Only support a single action per rule */
		if (*action)
			return -EINVAL;

		if (is_tcf_gact_shot(a)) {
			*action |= MLX5_FLOW_CONTEXT_ACTION_DROP;
			if (MLX5_CAP_FLOWTABLE(priv->mdev,
					       flow_table_properties_nic_receive.flow_counter))
				*action |= MLX5_FLOW_CONTEXT_ACTION_COUNT;
			continue;
		}

		if (is_tcf_skbedit_mark(a)) {
			u32 mark = tcf_skbedit_mark(a);

			if (mark & ~MLX5E_TC_FLOW_ID_MASK) {
				netdev_warn(priv->netdev, "Bad flow mark - only 16 bit is supported: 0x%x\n",
					    mark);
				return -EINVAL;
			}

			*flow_tag = mark;
			*action |= MLX5_FLOW_CONTEXT_ACTION_FWD_DEST;
			continue;
		}

		return -EINVAL;
	}

	return 0;
}

static int parse_tc_fdb_actions(struct mlx5e_priv *priv, struct tcf_exts *exts,
				struct mlx5_esw_flow_attr *attr)
{
	const struct tc_action *a;

	if (tc_no_actions(exts))
		return -EINVAL;

	memset(attr, 0, sizeof(*attr));
	attr->in_rep = priv->ppriv;

	tc_for_each_action(a, exts) {
		if (is_tcf_gact_shot(a)) {
			attr->action |= MLX5_FLOW_CONTEXT_ACTION_DROP |
					MLX5_FLOW_CONTEXT_ACTION_COUNT;
			continue;
		}

		if (is_tcf_mirred_egress_redirect(a)) {
			int ifindex = tcf_mirred_ifindex(a);
			struct net_device *out_dev;
			struct mlx5e_priv *out_priv;

			out_dev = __dev_get_by_index(dev_net(priv->netdev), ifindex);

			if (!switchdev_port_same_parent_id(priv->netdev, out_dev)) {
				pr_err("devices %s %s not on same switch HW, can't offload forwarding\n",
				       priv->netdev->name, out_dev->name);
				return -EINVAL;
			}

			attr->action |= MLX5_FLOW_CONTEXT_ACTION_FWD_DEST |
					MLX5_FLOW_CONTEXT_ACTION_COUNT;
			out_priv = netdev_priv(out_dev);
			attr->out_rep = out_priv->ppriv;
			continue;
		}

		if (is_tcf_vlan(a)) {
			if (tcf_vlan_action(a) == TCA_VLAN_ACT_POP) {
				attr->action |= MLX5_FLOW_CONTEXT_ACTION_VLAN_POP;
			} else if (tcf_vlan_action(a) == TCA_VLAN_ACT_PUSH) {
				if (tcf_vlan_push_proto(a) != htons(ETH_P_8021Q))
					return -EOPNOTSUPP;

				attr->action |= MLX5_FLOW_CONTEXT_ACTION_VLAN_PUSH;
				attr->vlan = tcf_vlan_push_vid(a);
			} else { /* action is TCA_VLAN_ACT_MODIFY */
				return -EOPNOTSUPP;
			}
			continue;
		}

		return -EINVAL;
	}
	return 0;
}

int mlx5e_configure_flower(struct mlx5e_priv *priv, __be16 protocol,
			   struct tc_cls_flower_offload *f)
{
	struct mlx5e_tc_table *tc = &priv->fs.tc;
	int err, attr_size = 0;
	u32 flow_tag, action;
	struct mlx5e_tc_flow *flow;
	struct mlx5_flow_spec *spec;
	struct mlx5_eswitch *esw = priv->mdev->priv.eswitch;
	u8 flow_flags = 0;

	if (esw && esw->mode == SRIOV_OFFLOADS) {
		flow_flags = MLX5E_TC_FLOW_ESWITCH;
		attr_size  = sizeof(struct mlx5_esw_flow_attr);
	}

	flow = kzalloc(sizeof(*flow) + attr_size, GFP_KERNEL);
	spec = mlx5_vzalloc(sizeof(*spec));
	if (!spec || !flow) {
		err = -ENOMEM;
		goto err_free;
	}

	flow->cookie = f->cookie;
	flow->flags = flow_flags;

	err = parse_cls_flower(priv, flow, spec, f);
	if (err < 0)
		goto err_free;

	if (flow->flags & MLX5E_TC_FLOW_ESWITCH) {
		flow->attr  = (struct mlx5_esw_flow_attr *)(flow + 1);
		err = parse_tc_fdb_actions(priv, f->exts, flow->attr);
		if (err < 0)
			goto err_free;
		flow->rule = mlx5e_tc_add_fdb_flow(priv, spec, flow->attr);
	} else {
		err = parse_tc_nic_actions(priv, f->exts, &action, &flow_tag);
		if (err < 0)
			goto err_free;
		flow->rule = mlx5e_tc_add_nic_flow(priv, spec, action, flow_tag);
	}

	if (IS_ERR(flow->rule)) {
		err = PTR_ERR(flow->rule);
		goto err_del_rule;
	}

	err = rhashtable_insert_fast(&tc->ht, &flow->node,
				     tc->ht_params);
	if (err)
		goto err_del_rule;

	goto out;

err_del_rule:
	mlx5e_tc_del_flow(priv, flow);

err_free:
	kfree(flow);
out:
	kvfree(spec);
	return err;
}

int mlx5e_delete_flower(struct mlx5e_priv *priv,
			struct tc_cls_flower_offload *f)
{
	struct mlx5e_tc_flow *flow;
	struct mlx5e_tc_table *tc = &priv->fs.tc;

	flow = rhashtable_lookup_fast(&tc->ht, &f->cookie,
				      tc->ht_params);
	if (!flow)
		return -EINVAL;

	rhashtable_remove_fast(&tc->ht, &flow->node, tc->ht_params);

	mlx5e_tc_del_flow(priv, flow);

	kfree(flow);

	return 0;
}

int mlx5e_stats_flower(struct mlx5e_priv *priv,
		       struct tc_cls_flower_offload *f)
{
	struct mlx5e_tc_table *tc = &priv->fs.tc;
	struct mlx5e_tc_flow *flow;
	struct tc_action *a;
	struct mlx5_fc *counter;
	u64 bytes;
	u64 packets;
	u64 lastuse;

	flow = rhashtable_lookup_fast(&tc->ht, &f->cookie,
				      tc->ht_params);
	if (!flow)
		return -EINVAL;

	counter = mlx5_flow_rule_counter(flow->rule);
	if (!counter)
		return 0;

	mlx5_fc_query_cached(counter, &bytes, &packets, &lastuse);

	preempt_disable();

	tc_for_each_action(a, f->exts)
		tcf_action_stats_update(a, bytes, packets, lastuse);

	preempt_enable();

	return 0;
}

static const struct rhashtable_params mlx5e_tc_flow_ht_params = {
	.head_offset = offsetof(struct mlx5e_tc_flow, node),
	.key_offset = offsetof(struct mlx5e_tc_flow, cookie),
	.key_len = sizeof(((struct mlx5e_tc_flow *)0)->cookie),
	.automatic_shrinking = true,
};

int mlx5e_tc_init(struct mlx5e_priv *priv)
{
	struct mlx5e_tc_table *tc = &priv->fs.tc;

	tc->ht_params = mlx5e_tc_flow_ht_params;
	return rhashtable_init(&tc->ht, &tc->ht_params);
}

static void _mlx5e_tc_del_flow(void *ptr, void *arg)
{
	struct mlx5e_tc_flow *flow = ptr;
	struct mlx5e_priv *priv = arg;

	mlx5e_tc_del_flow(priv, flow);
	kfree(flow);
}

void mlx5e_tc_cleanup(struct mlx5e_priv *priv)
{
	struct mlx5e_tc_table *tc = &priv->fs.tc;

	rhashtable_free_and_destroy(&tc->ht, _mlx5e_tc_del_flow, priv);

	if (!IS_ERR_OR_NULL(tc->t)) {
		mlx5_destroy_flow_table(tc->t);
		tc->t = NULL;
	}
}
