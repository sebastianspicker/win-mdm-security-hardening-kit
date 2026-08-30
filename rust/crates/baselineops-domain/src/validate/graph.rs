use std::collections::{BTreeMap, BTreeSet};

use crate::{ActionId, DomainResult};

use super::{TopologicalOrder, validation};

pub(super) fn validate_dependency_graph<T>(
    items: &[T],
    id: impl Fn(&T) -> ActionId,
    dependencies: impl Fn(&T) -> &[ActionId],
    validate: impl Fn(&T) -> DomainResult<()>,
) -> DomainResult<TopologicalOrder> {
    if items.is_empty() {
        return validation("profiles and plans must contain at least one action");
    }

    let index = validate_and_index(items, &id, &validate)?;
    let mut dependency_index = index_dependencies(items, &id, &dependencies, &index)?;
    let order = topological_sort(
        items,
        &id,
        &mut dependency_index.remaining,
        &dependency_index.children,
    );
    if order.len() != items.len() {
        return dependency_cycle(items, &id, &dependency_index.remaining);
    }
    Ok(TopologicalOrder(order))
}

fn validate_and_index<T>(
    items: &[T],
    id: &impl Fn(&T) -> ActionId,
    validate: &impl Fn(&T) -> DomainResult<()>,
) -> DomainResult<BTreeMap<ActionId, usize>> {
    let mut index = BTreeMap::new();
    for (position, item) in items.iter().enumerate() {
        validate(item)?;
        if index.insert(id(item), position).is_some() {
            return validation("profile or plan contains duplicate action IDs");
        }
    }
    Ok(index)
}

fn index_dependencies<T>(
    items: &[T],
    id: &impl Fn(&T) -> ActionId,
    dependencies: &impl Fn(&T) -> &[ActionId],
    index: &BTreeMap<ActionId, usize>,
) -> DomainResult<DependencyIndex> {
    let mut remaining_dependencies = vec![0_usize; items.len()];
    let mut children: BTreeMap<ActionId, Vec<usize>> = BTreeMap::new();
    for (position, item) in items.iter().enumerate() {
        index_item_dependencies(
            item,
            position,
            id,
            dependencies,
            index,
            &mut remaining_dependencies,
            &mut children,
        )?;
    }
    Ok(DependencyIndex {
        remaining: remaining_dependencies,
        children,
    })
}

struct DependencyIndex {
    remaining: Vec<usize>,
    children: BTreeMap<ActionId, Vec<usize>>,
}

fn index_item_dependencies<T>(
    item: &T,
    position: usize,
    id: &impl Fn(&T) -> ActionId,
    dependencies: &impl Fn(&T) -> &[ActionId],
    index: &BTreeMap<ActionId, usize>,
    remaining_dependencies: &mut [usize],
    children: &mut BTreeMap<ActionId, Vec<usize>>,
) -> DomainResult<()> {
    let mut seen_dependencies = BTreeSet::new();
    for dependency in dependencies(item) {
        if !seen_dependencies.insert(*dependency) {
            return validation("an action lists the same dependency more than once");
        }
        if !index.contains_key(dependency) {
            return validation(&format!(
                "action {} depends on unknown action {}",
                id(item),
                dependency
            ));
        }
        remaining_dependencies[position] += 1;
        children.entry(*dependency).or_default().push(position);
    }
    Ok(())
}

fn topological_sort<T>(
    items: &[T],
    id: &impl Fn(&T) -> ActionId,
    remaining_dependencies: &mut [usize],
    children: &BTreeMap<ActionId, Vec<usize>>,
) -> Vec<ActionId> {
    let mut ready = remaining_dependencies
        .iter()
        .enumerate()
        .filter_map(|(position, remaining)| (*remaining == 0).then_some(position))
        .collect::<BTreeSet<_>>();
    let mut order = Vec::with_capacity(items.len());
    while let Some(position) = ready.pop_first() {
        let item_id = id(&items[position]);
        order.push(item_id);
        release_dependents(item_id, children, remaining_dependencies, &mut ready);
    }
    order
}

fn release_dependents(
    item_id: ActionId,
    children: &BTreeMap<ActionId, Vec<usize>>,
    remaining_dependencies: &mut [usize],
    ready: &mut BTreeSet<usize>,
) {
    let Some(dependents) = children.get(&item_id) else {
        return;
    };
    for dependent in dependents {
        remaining_dependencies[*dependent] -= 1;
        if remaining_dependencies[*dependent] == 0 {
            ready.insert(*dependent);
        }
    }
}

fn dependency_cycle<T>(
    items: &[T],
    id: &impl Fn(&T) -> ActionId,
    remaining_dependencies: &[usize],
) -> DomainResult<TopologicalOrder> {
    let cycle_members = items
        .iter()
        .enumerate()
        .filter(|(position, _)| remaining_dependencies[*position] != 0)
        .map(|(_, item)| id(item).to_string())
        .collect::<Vec<_>>()
        .join(", ");
    validation(&format!(
        "action dependency graph contains a cycle: {cycle_members}"
    ))
}
