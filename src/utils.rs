use std::collections::{HashMap, HashSet};
use std::hash::Hash;

/// accurately inserts the @value into the set found at key @key. Creates set if @key is not yet
/// within @themap.
pub(crate) fn add_to_hashmap_set<T, U>(themap: &mut HashMap<T, HashSet<U>>, key: &T, value: &U)
where
    T: Eq,
    T: Hash,
    T: Copy,
    U: Eq,
    U: Hash,
    U: Copy,
{
    // key is already in out hashmap, just add to existing set.
    if let Some(theset) = themap.get_mut(key) {
        theset.insert(*value);
        return;
    }

    // there's no set yet. generate one than add it.
    let mut theset: HashSet<U> = HashSet::new();
    theset.insert(*value);
    themap.insert(*key, theset);
}

/// for each key, k, that is common between @map_a and @map_b, this function calculates the
/// intersection, i, between @map_a.get(k) and @map_b.get(k) and inserts <k,i> into @map_result.
pub(crate) fn intersect_hashmap_sets<T, U>(
    map_a: &HashMap<T, HashSet<U>>,
    map_b: &HashMap<T, HashSet<U>>,
    map_result: &mut HashMap<T, HashSet<U>>,
) where
    T: Eq,
    T: Hash,
    T: Copy,
    U: Eq,
    U: Hash,
    U: Copy,
{
    for (key, value_set_a) in map_a.iter() {
        // key is not in other map, no intersect, skip it.
        if !map_b.contains_key(key) {
            continue;
        }

        // safe unwrap.
        let mut value_set_b = map_b.get(key).unwrap();

        // get a hashset for the intersection, then add it to the result hashmap
        let mut hashset_intersect: HashSet<U> =
            value_set_a.intersection(value_set_b).cloned().collect();
        map_result.insert(*key, hashset_intersect);
    }
}

/// Returns a Union over all value sets within a hashmap @themap
pub(crate) fn collaps_hashmap_sets_via_union<T, U>(themap: &HashMap<T, HashSet<U>>) -> HashSet<U>
where
    T: Eq,
    T: Hash,
    T: Copy,
    U: Eq,
    U: Hash,
    U: Copy,
{
    let mut collapsed: HashSet<U> = HashSet::new();
    for (_, value_set) in themap.iter() {
        collapsed.extend(value_set);
    }
    collapsed
}
