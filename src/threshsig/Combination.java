package threshsig;

import java.lang.reflect.Array;

public class Combination<T> {
	
	private Class<T[]> clazz;		// class of T
	private T[] input;				// input array
	private int k; 					// size of dest arrays
	
	private int[] indexes;
	
	private int currIter;
	
	public Combination(Class<T[]> clazz, T[] input, int k) {
		this.clazz = clazz;
		this.input = input;
		this.k = k;
		this.indexes = new int[k];
	}
	
	public T[] generateNext() {
		
		if (k <= input.length) {
			
			if (currIter == 0) {
				currIter++;
			    // first index sequence: 0, 1, 2, ...
			    for (int i = 0; (indexes[i] = i) < k - 1; i++);  
			    return getSubset(input, indexes);
			} else {
				
		        int i;
		        // find position of item that can be incremented
		        for (i = k - 1; i >= 0 && indexes[i] == input.length - k + i; i--); 
		        if (i < 0) {
		            return null;
		        }
		        indexes[i]++;              // increment this item
		        for (++i; i < k; i++) {    // fill up remaining items
		        	indexes[i] = indexes[i - 1] + 1; 
		        }
		        return getSubset(input, indexes);
			}
		}
		return null;
	}
	
	// generate actual subset by index sequence
	private T[] getSubset(T[] input, int[] subset) {
		T[] result = (T[]) clazz.cast(Array.newInstance(clazz.getComponentType(), subset.length)); 
	    for (int i = 0; i < subset.length; i++) 
	        result[i] = input[subset[i]];
	    return result;
	}

}